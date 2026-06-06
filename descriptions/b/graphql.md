# graphql — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A request to a path ending in `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/playground`, `/graphiql`, or `/graphql/console`** → this is the canonical surface; dispatch immediately.
- **A POST whose JSON body has a top-level `query` (and often `variables` / `operationName`) string** → the `query: "{ ... }"` shape is the unmistakable GraphQL request envelope, regardless of the URL path it was sent to.
- **A response body shaped `{"data": {...}}` and/or `{"errors": [{"message": ...}]}`** → that `data`/`errors` envelope is GraphQL-specific. If you see it returned with HTTP 200, it is almost certainly GraphQL even on an oddly-named endpoint.
- **An error string mentioning `Cannot query field`, `Did you mean`, `Syntax Error`, `Unknown argument`, `must be of type`, or `__typename`** → these are graphql-js / Apollo / Yoga parser/validation messages. The presence of `Did you mean "user"?`-style suggestions is itself a high-value tell (schema leaks even with introspection off).
- **A response to `{"query":"{ __typename }"}` returning `{"data":{"__typename":"Query"}}`** → confirmed live GraphQL endpoint; dispatch.
- **A 400/422 saying `Must provide query string` or `GET query missing`** when you hit the bare path with no body → the server is a GraphQL endpoint complaining about a missing operation.
- **An HTML page that loads GraphiQL, Apollo Sandbox, Apollo Studio, Altair, or a "Playground" UI** → exposed in-browser IDE; treat as both a finding and a dispatch trigger.
- **A client JS bundle containing `gql\`...\``, `useQuery`, `useMutation`, `__APOLLO_STATE__`, `ApolloClient`, `Relay`, `urql`, or `apolloLink`** → the SPA talks GraphQL; the endpoint is in the bundle even if you have not seen the network call yet.
- **A response header `x-graphql-*`, or a `graphw00f` / fingerprint hit for Apollo, Yoga, Hasura, PostGraphile, Strawberry, graphene, Ariadne, async-graphql, Sangria, or graphql-java** → confirmed GraphQL server.
- **Any header in the `x-hasura-*` family being echoed, honored, or rejected (`x-hasura-role`, `x-hasura-user-id`, `x-hasura-admin-secret`)** → Hasura; the header-trust class is in play.
- **A single typed endpoint that returns deeply nested object data from one round-trip where a REST API would have needed many calls** → the "one endpoint, whole graph" smell of GraphQL.
- **Opaque base64 IDs in responses that decode to `Type:integer` (e.g. `VXNlcjox` → `User:1`)** → Relay global IDs; node-ID enumeration and IDOR territory.

## Use-case scenarios

- **A modern SPA / mobile backend.** When the front end is React/Vue/Angular and the network tab shows one fat POST returning a nested tree instead of dozens of REST GETs, the entire data and mutation surface is concentrated behind a single GraphQL endpoint. This is the prime case: one skill covers reads, writes, auth, and DoS for the whole app.
- **You found the endpoint but introspection is disabled.** This is exactly where the skill earns its keep — field-suggestion mining, `clairvoyance` reconstruction from "Did you mean" errors, wordlist guessing, and client-bundle harvesting of `gql` documents recover the schema anyway. Introspection-off is a soft control, not a stop sign.
- **Authorization testing on a typed graph.** GraphQL moves access control from route-level (which a REST scanner checks) down to per-resolver, per-field checks. The classic bug is a parent resolver that checks the role while a nested child resolver does not (`{ me { team { members { email } } } }` leaking peers). When you have a low-priv or anonymous session against a GraphQL app, dispatch here to walk every field, not just the entry query.
- **Rate-limit / brute-force evasion.** When you need to brute-force credentials, OTP/2FA codes, or password-reset tokens but a per-request limiter blocks you, GraphQL aliasing (one operation, N copies of `login`) and batching (a JSON array of operations sharing one bucket) let you fan out. Reach for this skill the moment the target is GraphQL and you are rate-limited.
- **IDOR / privilege escalation on mutations.** Schemas full of `updateUser`, `deleteAccount`, `setRole`, `grant*`, `impersonate*`, `reset*` mutations are an IDOR shopping list. Swap the ID argument (decoding Relay globals first) and verify cross-tenant change.
- **Server-side DoS assessment** where you have authorization to test resilience — nested-list depth multiplication, alias amplification, batching, directive flooding, recursive self-referential fragments (CVE-2022-37315 family), and `@defer`/`@stream` cost-hiding.
- **GraphQL as an injection front door.** When a `filter`/`where`/`orderBy` string, an `id`, a `url`/`webhook`/`image` arg, or a filename flows into a resolver, GraphQL is just the entry — probe it here, then pivot to `sqli`, `ssrf`, `cmdi`, `path-traversal`, or `file-upload` once a downstream sink fires.
- **WebSocket subscriptions** (`graphql-ws`, `subscriptions-transport-ws`): long-lived connections where the JWT is validated once at `connection_init` and never re-checked — test token revocation/expiry mid-stream and cross-tenant subscription IDs.
- **Federation / multi-subgraph setups** (Apollo Router, Hasura remote schemas): test whether subgraphs trust gateway-applied filtering, and whether you can call a subgraph directly to bypass gateway authz.

## Concrete tells (request → response examples)

- **Endpoint confirmation:**
  - `POST /graphql` body `{"query":"{ __typename }"}` → `{"data":{"__typename":"Query"}}` ⇒ live GraphQL, introspection or not.
- **Introspection enabled:**
  - `{"query":"{ __schema { queryType { name } } }"}` → `{"data":{"__schema":{"queryType":{"name":"Query"}}}}` ⇒ full `IntrospectionQuery` will dump the schema; production introspection is itself a finding.
- **Introspection disabled but suggestions on:**
  - `{"query":"{ usr { id } }"}` → `{"errors":[{"message":"Cannot query field \"usr\" on type \"Query\". Did you mean \"user\"?"}]}` ⇒ schema leaks field-by-field; mine with `clairvoyance`.
- **Wrong field type / validation leak:**
  - `{"query":"{ user(id: \"x\") { id } }"}` → `{"errors":[{"message":"Expected type \"ID!\", found \"x\"."}]}` ⇒ argument names and types are disclosed.
- **GET-mode + cookie auth (CSRF):**
  - `GET /graphql?query={__typename}` returns `{"data":{"__typename":"Query"}}` instead of "must POST" ⇒ GET mode is on; a `mutation` over GET is CSRF-able if auth is cookie-based.
- **Batching accepted:**
  - body `[{"query":"{__typename}"},{"query":"{__typename}"}]` → `[{"data":...},{"data":...}]` (a JSON array of results) ⇒ batching enabled; rate-limit fan-out is possible.
- **Relay global IDs:**
  - a response field `"id":"VXNlcjox"` where `echo VXNlcjox | base64 -d` → `User:1` ⇒ enumerable internals; pivot through `node(id: "VXNlcjoy")`.
- **Hasura header trust:**
  - resend a query adding `x-hasura-role: admin` and the response now includes admin-only fields under a non-admin JWT ⇒ header-trust authz bypass.
- **Exposed IDE:** `GET /graphiql` or `/graphql/console` returns a full HTML page that loads the in-browser query editor ⇒ exposed Sandbox/Playground.

## When NOT to use it / easily-confused-with

- **A REST/JSON API that merely returns JSON is not GraphQL.** The distinguishing marks are a request body with a top-level `query` string AND a response wrapped in `{"data": ...}` / `{"errors": [...]}`. A plain `{"users": [...]}` REST response is `api-testing` / IDOR territory, not this skill.
- **gRPC, JSON-RPC, OData, or SOAP** can also collapse many calls into one endpoint, but their envelopes differ (`jsonrpc`, `$metadata`, SOAP XML, protobuf). Do not route those here.
- **An injection that happens to enter through a GraphQL argument is owned by the downstream skill once the primitive is confirmed.** Use this skill to find the sink and shape the operation, then hand off: a SQL error from a `filter` string → `sqli`; an out-of-band callback from a `url` arg → `ssrf`; a shell artifact → `cmdi`; `../` in a multipart filename → `path-traversal`/`file-upload`. GraphQL is the entry, not the whole bug.
- **A reflected argument value in an error message is information disclosure, not auto-IDOR or injection** — only count it once the actual primitive fires (cross-tenant read/write reproduced as the victim, OOB callback received, SQL/file artifact observed).
- **Don't gate on HTTP status.** GraphQL almost always returns 200 even on errors; a 200 with a populated `errors` array is the norm, not a pass. Conversely a 400 "Must provide query string" still confirms a GraphQL endpoint.
- **Introspection / field suggestions on an intentionally public developer portal** is expected behavior, not a finding — confirm the host/DNS/TLS match the real production target before reporting.
- **A GraphQL-looking path that 404s or returns ordinary HTML** with no `data`/`errors` envelope and no `query`-body handling is not a live endpoint — keep hunting in JS bundles before committing this skill.

B:graphql done

