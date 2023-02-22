# SIRE
SIRE is an infrastructure that supports remote attestation, application membership management, auditable integrity-protected logging and coordination primitives. This project was developed by the LaSIGE research unit at the University of Lisbon.

This package contains the source code (``\src``), dependencies (``\lib``), running scripts (``\runscripts``), and configuration files (``\config``).
SIRE requires Java 17.0.1 or later.


SIRE is composed by 4 entities:
- Server (``rep*`` folders)
- Proxy (``pro*`` folders)
- Device/Attester (``cli*`` folders)
- App Administrator (``man*`` folders)

#Quick Start
Before running SIRE, some configuration must be done regarding the location of each replica and proxy.

The servers address must be specified in the file ``config\hosts.config``:
```
#server id, address and port
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
Note: This address is used by the mock device provided. If you are using your own device, this can be disregarded.
The port should be ``2500 + proxyId``, e.g., for port 2501, your proxy should have id 1.
This id can be specified when running the proxy, as will be seen later.

# How to Compile
To compile, use the following command:
```
gradle localDeploy
```
If you do not have Gradle installed you can obtain it here: https://gradle.org/install/.

This command will create a directory on your Desktop with the name "SIRE".
Inside there will be multiple folders corresponding to each one of SIRE's entities.
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
- Server: ``sire.server.SireServer`` (Requires a number id as an argument, starting from 0. Configured for 4 replicas.)
- Proxy: ``sire.proxy.ProxyMain`` (Requires a number id as an argument and should match the port specified in the configuration file. Default configuration is for id 1.)
- Attester/Device: ``sire.device.DeviceClient``
- App Admin: ``sire.management.ManagementClient``

The existent client is a mock device that executes a variety of operations to demonstrate the usage of SIRE.

#How to Configure Applications

#How to Use
In this section, we will explain how to use SIRE with your own devices.

SIRE has the following operations available to devices:

Function | Description |
-------- | ----------- |
put(appId, deviceId, key, value) | Adds a new entry to storage |
delete(appId, deviceId, key) | Deletes an entry from storage |
getData(appId, deviceId, key) | Gets data associated with key from storage |
getList(appId, deviceId) | Gets list of all entries |
cas(appId, deviceId, key, oldValue, newValue) | If value of key is equal to oldValue, replaces it with newValue. |
 |  |
join(appId, deviceId) | Finish the attestation protocol and join the application’s membership |
leave(appId, deviceId) | Leave the system |
ping(appId, deviceId) | Assures the system that the device is still running |
getView(appId, deviceId) | Get current membership of application |

These operations can be accessed either through REST requests or through regular sockets.
Both interfaces are made available through the proxy.

## Sockets ##
Communication through sockets requires requests to be serialized with Protobuf, which can be compiled to a variety of
languages.
The structure of these requests (``ProxyMessage``) can be found in the file ``messages\messages.proto``, which also 
contains the structure of the responses (``ProxyResponse``) provided by SIRE.

## REST ##
Communication through REST can be done through the address defined for the proxy (``http:\\127.0.0.1:8080`` by default).
Each operation can be accessed as follows:

Function | Path |
-------- | ----------- |
put | PUT request on *sireaddress*/map?appId=*app* |
delete | DELETE request on *sireaddress*/map?appId=*app* |
getData | GET request on *sireaddress*/map?appId=*app* |
getList | GET request on *sireaddress*/mapList?appId=*app* |
cas | POST request on *sireaddress*/map?appId=*app* |
|  |
preJoin | PUT request on *sireaddress*/member?appId=*app* |
join | PUT request on *sireaddress*/member?appId=*app* |
leave | DELETE request on *sireaddress*/member?appId=*app* |
ping | PUT request on *sireaddress*/member?appId=*app* |
getView | GET request on *sireaddress*/view?appId=*app* |

The body of the requests should be in JSON format and all byte array values are expected to be encoded in Base64.


