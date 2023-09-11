# SIRE
SIRE is a project to establish an infrastructure that supports remote attestation, application membership management, auditable integrity-protected logging, and coordination primitives. This project was developed by the LASIGE research unit at the University of Lisbon.

This repository contains SIRE's implementation in Java 17.0.1[^1]. It contains four main folders: 
- the source code (``\src``)
- dependencies (``\lib``)
- running scripts (``\runscripts``)
- configuration files (``\config``).

[^1]: Later versions might have some incompatibilities, namely with Gradle.

# Quick Start
Before running SIRE, some configuration must be done regarding the location of each server (replica) and proxy.

The servers' addresses must be specified in the file ``config\hosts.config``:
```
#server id, address, and port
0 127.0.0.1 11000 11001
1 127.0.0.1 11010 11011
2 127.0.0.1 11020 11021
3 127.0.0.1 11030 11031
```
The proxy address can be specified in the file ``config\proxy.properties``:
```
ip=127.0.0.1
port=2501
```
The port should be ``2500 + proxyId``; e.g., for port 2501, the proxy should have id 1.
This id can be specified when running the proxy, as will be shown later.

**Note:** This address is only used by the mock device provided. If you are using your own device, this can be disregarded.

# How to Compile
After downloading the repository and unzipping it, change the current directory to the root directory of unzipped file and use the following command to compile the project:
```
gradle localDeploy
```
If you do not have Gradle installed, you can obtain it here: https://gradle.org/install/.

If this command completes successfully, ``BUILD SUCCESSFUL`` must be displayed. As a result, a directory will be created on your Desktop with the name "SIRE".
Inside there will be multiple folders corresponding to each of SIRE's entities:
- Server (``rep*`` folders)
- Proxy (``pro*`` folders)
- Device/Attester (``cli*`` folders)
- App Administrator (``man*`` folders)

# How to Run
Before executing any client (device or app admin), all the server replicas and proxy should be up and running.
To run an entity, first, change your current directory according to what entity you want to run; e.g., to run server 0, you should change your current directory to ``Desktop\SIRE\rep0``.  
Then, use the following command:  
(Command Line)
```
./run.cmd path [argument]
```
(Terminal)
```
smartrun.sh path
```
The ``path`` parameter must be determined based on the entity that you want to run:
- Server: ``sire.server.SireServer`` (Requires a server id as ``argument``, ranging from 0 to the greatest server id. e.g., ``./run.cmd sire.server.SireServer 0``)
- Proxy: ``sire.proxy.ProxyMain`` (Requires a proxy id as ``argument`` and should match the port specified in the configuration file. Default configuration is for id 1.)
- Attester/Device: ``sire.device.DeviceClient`` (Does not need any argument.)
- App Admin: ``sire.management.ManagementClient`` (Does not need any argument.)

The existent client is a mock device that executes various operations to demonstrate the usage of SIRE.
This mock device starts by attesting itself and then executes a series of operations on the Coordination Manager (puts, gets, deletes) as well as some operations on the Membership Manager(ping, getView).
The management client simply adds and fetches an extension.

# How to Configure Applications
You can configure remote attestation policies and extensions for your own applications.

The following operations are available to app administrators:

Function | Description |
-------- | ----------- |
 addExtension(appId, type, key, code) | Adds extension for app with id *appId* to be executed when an operation of a given type is called with the given key. The given type and key can be null. The code will be stored associated with extensionKey (appId + type + key, in this order).
 removeExtension(appId, type, key) | Removes extension associated with extensionKey (appId + type + key, in this order). The given type/key can be null.
 getExtension(appId, type, key) | Gets the code of the extension associated with extensionKey (appId + type + key). The given type/key can be null.
|  |
 setPolicy(appId, policy) | Sets policy from app with id *appId* |
 deletePolicy(appId) | Deletes policy from app with id *appId* |
 getPolicy(appId) | Gets policy from app with id *appId* |
|  |
 getView(appId) | Get current membership of application |


These operations can be accessed through REST requests, regular sockets, or a user-friendly web interface (see the ``src\...\sire\api\management_login.html`` file, user is 'admin', password is 'appadmin').
All these interfaces are made available through the proxy.

Both the policy and extensions must be implemented in Groovy.
In the case of the policy, the Groovy script should have a ``verifyEvidence`` method that takes an ``Evidence`` object as input
(see file ``src\...\sire\attestation\Evidence.java``).

<details><summary>Example Policy</summary>
<p>

```groovy
package sire.attestation
                                
def verifyEvidence(Evidence e) {
    def refValues = ["measure1".bytes, "measure2".bytes]
    def isClaimValid = false
    for(value in refValues) {
        if(value == e.getClaim())
            isClaimValid = true
        }
        def endorsedKeys = [[3, -27, -103, 52, -58, -46, 91, -103, -14, 0, 65, 73, -91, 31, -42, -97,
                                         77, 19, -55, 8, 125, -9, -82, -117, -70, 102, -110, 88, -121, -76, -88, 44, -75] as byte[]]
        def isKeyValid = false
        for(key in endorsedKeys) {
            if(key == e.getPubKey())
                isKeyValid = true
            }
        def expectedVersion = "1.0"
        return isClaimValid && isKeyValid && expectedVersion.equals(e.getVersion())
}
```
</p>
</details>

In the case of the extension, the script should have a ``runExtension`` method that takes an ``ExtParams`` object as input
(see file ``src\...\sire\coordination\ExtParams.java``).

<details><summary>Example Extension</summary>
<p>
This is an example extension that is used to perform intersection management for the autonomous vehicle scenario.

Example key: ``app1EXT_PUT``

Example extension:
```groovy
 package sire.coordination

def runExtension(ExtParams p) {
 def temp = new int[3]
 CoordinationManager store = CoordinationManager.getInstance()
 def laneList = store.get(p.getAppId(), "lanes")
 String str = p.getKey().charAt(p.getKey().length() - 1)
 int lane = str as int
 def b = p.getValue()[0]

 if (b == (1 as byte) && laneList[lane] == (1 as byte))
  return new ExtParams(p.getAppId(), "lanes", laneList, null, false)

 switch (lane) {
  case 0:
   temp = [0, 6, 7] as int[]
   break
  case 1:
   temp = [1, 2, 3] as int[]
   break
  case 2:
   temp = [0, 1, 2] as int[]
   break
  case 3:
   temp = [3, 4, 5] as int[]
   break
  case 4:
   temp = [2, 3, 4] as int[]
   break
  case 5:
   temp = [5, 6, 7] as int[]
   break
  case 6:
   temp = [4, 5, 6] as int[]
   break
  case 7:
   temp = [0, 1, 7] as int[]
   break
 }

 for (i in temp) {
  laneList[i] = b
 }
 ExtParams res = new ExtParams(p.getAppId(), "lanes", laneList, null, true)

 return res;
}
```

</p>
</details>

# How to Use
Here, we will explain how to use SIRE with your own devices.

SIRE has the following operations available to devices:

Function | Description |
-------- | ----------- |
put(appId, deviceId, key, value) | Adds a new entry to storage |
delete(appId, deviceId, key) | Deletes an entry from storage |
getData(appId, deviceId, key) | Gets data associated with key from storage |
getList(appId, deviceId) | Gets list of all entries |
cas(appId, deviceId, key, oldValue, newValue) | If value of key is equal to oldValue, replace it with newValue. |
 |  |
preJoin(appId, deviceId, pubKey, signature) | Start the attestation protocol |
join(appId, deviceId, pubKey, evidence, signature) | Finish the attestation protocol and join the application’s membership |
leave(appId, deviceId) | Leave the system |
ping(appId, deviceId) | Assures the system that the device is still running |
getView(appId, deviceId) | Get current membership of application |

These operations can be accessed either through REST requests or regular sockets.
Both interfaces are made available through the proxy.

## Sockets ##
Communication through sockets requires requests to be serialized with Protobuf, which can be compiled into a variety of
languages.
The structure of these requests (``ProxyMessage``) can be found in the file ``messages\messages.proto``, which also 
contains the structure of the responses (``ProxyResponse``) provided by SIRE.

## REST ##
Communication through REST can be done through the endpoint address defined for the proxy (``http:\\127.0.0.1:8080`` by default).
Each operation can be accessed as follows:

Function | Path |
-------- | ----------- |
put | PUT request on *sireaddress*/map?appId=*app* |
delete | DELETE request on *sireaddress*/map?appId=*app* |
getData | GET request on *sireaddress*/map?appId=*app* |
getList | GET request on *sireaddress*/mapList?appId=*app* |
cas | POST request on *sireaddress*/map?appId=*app* |
|  |
preJoin | POST request on *sireaddress*/member?appId=*app* |
join | PUT request on *sireaddress*/member?appId=*app* |
leave | DELETE request on *sireaddress*/member?appId=*app* |
ping | PUT request on *sireaddress*/ping?appId=*app* |
getView | GET request on *sireaddress*/view?appId=*app* |

The body of the requests should be in JSON format, and all byte array values are expected to be encoded in Base64.
The format of the requests and responses can be found in the ``RESTRequests.java`` and ``RESTResponses.java``, respectively.



