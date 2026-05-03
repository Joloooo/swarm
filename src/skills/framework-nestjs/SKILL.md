---
name: framework-nestjs
description: Use when the target is a NestJS application — TypeScript Node.js framework with guards, pipes, decorators, modular DI, and multiple transports (HTTP, WebSocket, microservices, gRPC). Covers NestJS-specific attack surface (guard gaps across decorator stacks, ValidationPipe whitelist / nested-validation bypass, `@Public()` over-application, ExecutionContext mismatches between HTTP / WS / RPC, Reflector metadata key mismatches, ClassSerializerInterceptor leaks, CacheInterceptor key confusion, `@Global()` module exposure, request-scoped provider misconfiguration, microservice transport handlers (`@MessagePattern`) lacking guards, TypeORM / Prisma / Mongoose injection, `@SkipThrottle()` on sensitive endpoints, CRUD-generator authorization gaps, GraphQL playground exposure). Reference-only knowledge that vulnerability-class skills consult when reconnaissance fingerprints NestJS.
---

# NestJS

Stack-specific testing knowledge for NestJS applications.

This skill is **reference-only** — it has no `agent_id`. The
planner and active vulnerability-class agents consult it when
reconnaissance fingerprints NestJS (typical signals:
`x-powered-by: Express`, route patterns like
`/api/v1/<controller>/<id>`, NestJS-style validation error
envelopes, `@Controller` / `@Module` source artifacts in client
bundles).

## Attack Surface

**Decorator pipeline**:
- **Guards** — `@UseGuards`, `CanActivate`, execution context
  (HTTP / WS / RPC), `Reflector` metadata.
- **Pipes** — `ValidationPipe` (`whitelist`, `transform`,
  `forbidNonWhitelisted`), `ParseIntPipe`, custom pipes.
- **Interceptors** — response mapping, caching, logging, timeout
  — can modify request / response flow.
- **Filters** — exception filters that may leak information.
- **Metadata** — `@SetMetadata`, `@Public()`, `@Roles()`,
  `@Permissions()`.

**Module system**:
- `@Module` boundaries, provider scoping (`DEFAULT` / `REQUEST` /
  `TRANSIENT`).
- Dynamic modules — `forRoot` / `forRootAsync`, global modules.
- DI container — provider overrides, custom providers.

**Controllers & transports**:
- REST — `@Controller`, versioning (URI / header / media type).
- GraphQL — `@Resolver`, playground / sandbox exposure.
- WebSocket — `@WebSocketGateway`, gateway guards, room
  authorization.
- Microservices — TCP, Redis, NATS, MQTT, gRPC, Kafka — often
  lack HTTP-level auth.

**Data layer**:
- TypeORM — repositories, `QueryBuilder`, raw queries, relations.
- Prisma — `$queryRaw`, `$queryRawUnsafe`.
- Mongoose — operator injection, `$where`, `$regex`.

**Auth & config**:
- `@nestjs/passport` strategies, `@nestjs/jwt`, session-based auth.
- `@nestjs/config`, `ConfigService`, `.env` files.
- `@nestjs/throttler`, rate limiting with `@SkipThrottle`.

**API documentation** — `@nestjs/swagger`: OpenAPI exposure, DTO
schemas, auth schemes.

## High-value targets

- Swagger / OpenAPI endpoints in production (`/api`, `/api-docs`,
  `/api-json`, `/swagger`).
- Auth endpoints — login, register, token refresh, password
  reset, OAuth callbacks.
- Admin controllers decorated with `@Roles('admin')` — test with
  user-level tokens.
- File-upload endpoints using `FileInterceptor` /
  `FilesInterceptor`.
- WebSocket gateways sharing business logic with HTTP
  controllers.
- Microservice handlers (`@MessagePattern`, `@EventPattern`) —
  often unguarded.
- CRUD generators (`@nestjsx/crud`) with auto-generated
  endpoints.
- Background jobs and scheduled tasks (`@nestjs/schedule`).
- Health / metrics endpoints (`@nestjs/terminus`, `/health`,
  `/metrics`).
- GraphQL playground / sandbox in production (`/graphql`).

## Reconnaissance

### Swagger discovery
```
GET /api
GET /api-docs
GET /api-json
GET /swagger
GET /docs
GET /v1/api-docs
GET /api/v2/docs
```
Extract paths, parameter schemas, DTOs, auth schemes, example
values. Swagger may reveal internal endpoints, deprecated routes,
and admin-only paths not visible in the UI.

### Guard mapping
For each controller and method, identify:
- Global guards (applied in `main.ts` or app module).
- Controller-level guards (`@UseGuards` on the class).
- Method-level guards (`@UseGuards` on individual handlers).
- `@Public()` or `@SkipThrottle()` decorators that bypass
  protection.

## Vulnerability classes

### Guard bypass

**Decorator-stack gaps**:
- Guards execute global → controller → method. A method missing
  `@UseGuards` when siblings have it is the #1 finding.
- `@Public()` metadata causing global `AuthGuard` to skip
  enforcement — check if applied too broadly.
- New methods added to existing controllers without inheriting the
  expected guard.

**ExecutionContext switching**:
- Guards handling only HTTP context (`getRequest()`) may fail
  silently on WebSocket or RPC, returning `true` by default.
- Test the same business logic through alternate transports to
  find context-specific bypasses.

**Reflector mismatches**:
- Guard reads `SetMetadata('roles', [...])` but decorator sets
  `'role'` (singular) — guard sees no metadata, defaults to
  allow.
- `applyDecorators()` compositions accidentally overriding
  stricter guards with permissive ones.

### ValidationPipe exploits

**Whitelist bypass**:
- `whitelist: true` without `forbidNonWhitelisted: true` — extra
  properties silently stripped but may have been processed by
  earlier middleware / interceptors.
- Missing `@Type(() => ChildDto)` on nested objects —
  `@ValidateNested()` without `@Type` means nested payload is
  never validated.
- Array elements — `@IsArray()` doesn't validate elements without
  `@ValidateNested({ each: true })` and `@Type`.

**Type coercion**:
- `transform: true` enables implicit coercion — strings →
  numbers, `"true"` → `true`, `"null"` → `null`. Exploit
  truthiness assumptions in business logic downstream.

**Conditional validation**:
- `@ValidateIf()` and validation groups creating paths where
  fields skip validation entirely.

**Missing parse pipes**:
- `@Param('id')` without `ParseIntPipe` / `ParseUUIDPipe` —
  string values reach ORM queries directly.

### Auth & Passport

**JWT strategy**:
- Check `ignoreExpiration` is false, `algorithms` is pinned (no
  `none` or HS / RS confusion).
- Weak `secretOrKey` values.
- Cross-service token reuse when audience / issuer not enforced.

**Passport-strategy issues**:
- `validate()` return value becomes `req.user` — if it returns the
  full DB record, sensitive fields leak downstream.
- Multiple strategies (JWT + session) — one may bypass
  restrictions of the other.
- Custom guards returning `true` for unauthenticated as "optional
  auth".

**Timing attacks**: plain string comparison instead of bcrypt /
argon2 in local strategy.

### Serialization leaks

**Missing `ClassSerializerInterceptor`**:
- If not applied globally, `@Exclude()` fields (passwords,
  internal IDs) are returned in responses.
- `@Expose()` with groups — admin-only fields exposed when groups
  not enforced per-request.

**Circular relations**:
- Eager-loaded TypeORM / Prisma relations exposing entire object
  graph without careful serialization.

### Interceptor abuse

**Cache poisoning**:
- `CacheInterceptor` without user / tenant identity in cache key
  — responses from one user served to another.
- Test — authenticated request, then unauthenticated request
  returning cached data.

**Response mapping**:
- Transformation interceptors may leak internal entity fields if
  mapping is incomplete.

### Module-boundary leaks

**Global module exposure**:
- `@Global()` modules expose all providers to every module
  without explicit imports.
- Sensitive services (admin operations, internal APIs) accessible
  from untrusted modules.

**Config leaks**:
- `forRoot` / `forRootAsync` configuration secrets accessible via
  `ConfigService` injection in any module.

**Scope issues**:
- Request-scoped providers (`Scope.REQUEST`) incorrectly scoped as
  `DEFAULT` (singleton) — request context leaks across concurrent
  requests.

### WebSocket gateway

- HTTP guards DON'T automatically apply to WebSocket gateways —
  `@UseGuards` must be explicit.
- Authentication deferred from `handleConnection` to message
  handlers allows unauthenticated message sending.
- Room / namespace authorization — users joining rooms they
  shouldn't access.
- `@SubscribeMessage()` handlers relying on connection-level auth
  instead of per-message validation.

### Microservice transport

- `@MessagePattern` / `@EventPattern` handlers often lack guards
  (considered "internal").
- If transport (Redis, NATS, Kafka) is network-accessible,
  messages can be injected bypassing all HTTP security.
- `ValidationPipe` may only be configured for HTTP — microservice
  payloads skip validation.

### ORM injection

- **TypeORM** — `QueryBuilder` and `.query()` with template-
  literal interpolation → SQL injection. API allowing
  specification of which relations to load via query params.
- **Mongoose** — query-operator injection
  (`{ password: { $gt: "" } }`) via unsanitized request body;
  `$where` and `$regex` operators from user input.
- **Prisma** — `$queryRaw` / `$executeRaw` with string
  interpolation (not tagged template); `$queryRawUnsafe` usage.

### Rate limiting

- `@SkipThrottle()` on sensitive endpoints (login, password
  reset, OTP).
- In-memory throttler storage — resets on restart, doesn't work
  across instances.
- Behind proxy without `trust proxy` — all requests share the
  same IP, or header is spoofable.

### CRUD generators

- Auto-generated CRUD endpoints may not inherit manual
  guard configurations.
- Bulk operations (`createMany`, `updateMany`) bypassing
  per-entity authorization.
- Query-parameter injection in CRUD libraries — `filter`, `sort`,
  `join`, `select` exposing unauthorized data.

## Bypass techniques

- `@Public()` / skip-metadata applied via composed decorators at
  method level causing global guards to skip via `Reflector`
  metadata checks.
- Route-param pollution — `/users/123?id=456`; which `id` wins in
  guards vs. handlers?
- Version routing — v1 of endpoint may still be registered
  without the guard added to v2.
- `X-HTTP-Method-Override` or `_method` processed by Express
  before guards.
- Content-type switching — `application/x-www-form-urlencoded`
  instead of JSON to bypass JSON-specific validation.
- Exception-filter differences — guard throwing results in
  generic error that leaks route existence info.

## Workflow

1. **Enumerate** — fetch Swagger / OpenAPI; map all controllers,
   resolvers, and gateways.
2. **Guard audit** — map decorator stack per method (which
   guards, pipes, interceptors apply at each level).
3. **Matrix testing** — test each endpoint across unauth / user /
   admin × HTTP / WS / microservice.
4. **Validation probing** — send extra fields, wrong types,
   nested objects, arrays to find pipe gaps.
5. **Transport parity** — same operation via HTTP, WebSocket,
   microservice transport.
6. **Module boundaries** — check if providers from one module are
   accessible without proper imports.
7. **Serialization check** — compare raw entity fields with API
   response fields.

## Validation requirements

- Guard bypass — request to guarded endpoint succeeding without
  auth, showing guard-chain break point.
- Validation bypass — payload with extra / malformed fields
  affecting business logic.
- Cross-transport inconsistency — same action authorized via HTTP
  but exploitable via WebSocket / microservice.
- Module-boundary leak — accessing provider or data across
  unauthorized module boundaries.
- Serialization leak — response containing excluded fields
  (passwords, internal metadata).
- IDOR — side-by-side requests from different users showing
  unauthorized data access.
- ORM injection — raw query with user-controlled input returning
  unauthorized data, or error-based evidence of query structure.
- Cache poisoning — response from unauthenticated or
  different-user request matching a prior authenticated user's
  cached response.
