# SIRE
SIRE is a replicated infrastructure that supports remote attestation, application membership management, auditable integrity-protected storage and coordination primitives.  
SIRE is composed by 4 main entities:
- Server (rep* folders)
- Proxy (pro* folders)
- Attester (cli* folders)
- App Admin (man* folders)
# How to Compile
To compile, use the following command:
```
gradle localDeploy
```
This will create a directory on your Desktop with the name "SIRE". Inside there will be multiple folders corresponding to each one of SIRE's entities.
# How to Run
First, change your current directory according to what entity you want to run., e.g., to run server replica 0, you should change your directory to ``Desktop\SIRE\rep0``.  
Then, use the following command:  
(Command Line)
```
run.cmd [path to class]
```
(Terminal)
```
smartrun.sh [path to class]
```
List of paths for each entity:
- Server: ``sire.server.SireServer`` (Requires a number id as an argument, starting from 0. Is configured for 4 replicas.)
- Proxy: ``sire.proxy.ProxyMain`` (requires a number id as an argument. Is configured for proxyId = 1.)
- Attester: ``sire.dummy.Attester`` (requires a number id as an argument.)
- App Admin: ``sire.management.ManagementClient``
