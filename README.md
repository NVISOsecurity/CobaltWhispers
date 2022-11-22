# CobaltWhispers

Author: [@Cerbersec](https://twitter.com/cerbersec)

CobaltWhispers is an aggressor script that utilizes a collection of Beacon Object Files for Cobalt Strike to perform process injection, persistence and more, leveraging direct syscalls to bypass EDR/AV.

> CobaltWhispers is powered by [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) and [InlineWhispers2](https://github.com/Sh0ckFR/InlineWhispers2)  
> CobaltWhispers is based on [StayKit](https://github.com/0xthirteen/StayKit) and work from [Hasherezade](https://github.com/hasherezade/transacted_hollowing) and [Forrest Orr](https://github.com/forrest-orr/phantom-dll-hollower-poc).

CobaltWhispers was made as part of an internship at NVISO Security's Red Team. The associated blogposts can be found [here (process-injection)](https://cerbersec.com/2021/08/26/beacon-object-files-part-1.html) and [here (kernel karnage)](https://blog.nviso.eu/2021/10/21/kernel-karnage-part-1/).

## Injection
### SpawnProcess

| Payload Type | Target | Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: | :---: | :---: |
| - | - | 5 | No | Inherit permissions from parent process |

#### Description

Spawns a new suspended process with Code Integrity Guard (CIG) enabled to block non-Microsoft signed binaries. Spoofs the specified parent process. The PID is returned.

#### Parameters

**Parent process:** The name of the process to set as parent  
**Executable location:** Full path to executable on disk used to spawn new process

___

### CreateRemoteThread

| Payload Type | Target | Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: | :---: | :---: |
| Shellcode/Raw | PID | 5 | No | - |

#### Description

Injects a payload into a remote process using NtCreateThreadEx

#### Parameters

**Process PID:** The process ID of the remote process  
**Payload location:** Location of payload in binary form on disk (Conditional | Optional)  
**Payload b64:** Raw shellcode in base64 encoded string format (Conditional | Optional)  
**Listener:** Listener to generate payload for (Conditional)

A listener should be specified to generate a Beacon payload. If a manual payload is desired, it should be provided via a path to the raw binary on disk, or Base64 encoded shellcode.

___

### QueueUserAPC

| Payload Type | Target | Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: | :---: | :---: |
| Shellcode/Raw | PID | 2 | No | Potentially crash target process |

#### Description

Injects a payload into a remote process using NtQueueApcThread

#### Parameters

**Process PID:** The process ID of the remote process  
**Threads:** Number of threads to add an APC call to  
**Payload location:** Location of payload in binary form on disk (Conditional | Optional)  
**Payload b64:** Raw shellcode in base64 encoded string format (Conditional | Optional)  
**Listener:** Listener to generate payload for (Conditional)

A listener should be specified to generate a Beacon payload. If a manual payload is desired, it should be provided via a path to the raw binary on disk, or Base64 encoded shellcode.

___

### MapViewOfSection

| Payload Type | Target | Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: | :---: | :---: |
| Shellcode/Raw | Surrogate Process | 5 | No | - |

#### Description

Injects a payload into a surrogate process using NtMapViewOfSection

#### Parameters

**Parent process:** The name of the process to set as parent  
**Executable location:** The location of the executable on disk to be used to spawn a new process  
**Payload location:** Location of payload in binary form on disk (Conditional | Optional)  
**Payload b64:** Raw shellcode in base64 encoded string format (Conditional | Optional)  
**Listener:** Listener to generate payload for (Conditional)  

A listener should be specified to generate a Beacon payload. If a manual payload is desired, it should be provided via a path to the raw binary on disk, or Base64 encoded shellcode.

___

### TransactedHollowing

| Payload Type | Target | Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: | :---: | :---: |
| PE | Surrogate Process | 5 | No | Requires x64 PE payload |

#### Description

Injects a payload into a surrogate process using transacted sections and mapped views. Remote entry point and PEB are updated, no anomalous memory sections or memory permissions. See [here](https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/) for more information.

#### Parameters

**Parent process:** The name of the process to set as parent  
**Executable location:** The location of the executable on disk to be used to spawn a new process  
**Payload location:** Location of x64 PE payload on disk (Conditional | Optional)  
**Payload b64:** x64 PE payload in base64 encoded string format (Conditional | Optional)  
**Listener:** Listener to generate payload for (Conditional)

A listener should be specified to generate a Beacon payload. If a manual payload is desired, it should be provided via a path to the x64 PE on disk, or Base64 encoded x64 PE.

___

### PhantomDLLHollowing

**CURRENTLY NOT IMPLEMENTED**

| Payload Type | Target | Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: | :---: | :---: |
| Position Independent Shellcode (PIC) | Surrogate Process | 5 | Yes | Elevated permissions are required to open system DLLs with write permissions |

#### Description

Injects a payload into a surrogate process using transacted sections in combination with DLL hollowing. See [here](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing) for more information.

#### Parameters

**Parent process:** The name of the process to set as parent  
**Executable location:** The location of the executable on disk to be used to spawn a new process  
**Payload location:** Location of payload in binary form on disk (Conditional | Optional)  
**Payload b64:** Raw shellcode in base64 encoded string format (Conditional | Optional)  
**Listener:** Listener to generate payload for (Conditional)

A listener should be specified to generate a Beacon payload. If a manual payload is desired, it should be provided via a path to the raw binary on disk, or Base64 encoded shellcode.

___

## Persistence
### ElevatedRegKey
#### Description

Create or modify a registry key at the specified location.
* HKLM:Software\\Microsoft\\Windows\\CurrentVersion\\Run
* HKLM:Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce

#### Parameters

**Key name:** Value name  
**Command:** Command to be ran when registry is used  
**Registry key:** Location where registry key will be created  
**Hidden:** Will prepend a null byte to the key name; throws errors in regedit  
**Cleanup:** Removes created key

Cleanup requires the key name and registry key (location).

___

### ElevatedUserInitRegKey
#### Description

Create or modify a registry key at the specified location.
* HKLM:Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon [UserInit]

#### Parameters

**Key name:** Value name  
**Command:** Command to be ran when registry is used  
**Registry key:** Location where registry key will be created  
**Hidden:** Will prepend a null byte to the key name; throws errors in regedit  
**Cleanup:** Removes created key

Cleanup requires the key name and registry key (location).  
UserInit: Automatically sets 'Key name' and 'Registry key'.

___

### UserRegKey
#### Description
Create or modify a registry key at the specified location.
* HKCU:Software\\Microsoft\\Windows\\CurrentVersion\\Run
* HKCU:Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce

#### Parameters

**Key name:** Value name  
**Command:** Command to be ran when registry is used  
**Registry key:** Location where registry key will be created  
**Hidden:** Will prepend a null byte to the key name; throws errors in regedit  
**Cleanup:** Removes created key

Cleanup requires the key name and registry key (location).

___

### UserInitMprRegKey
#### Description
Create or modify a registry key at the specified location.
* HKCU:Environment [UserInitMprLogonScript]

#### Parameters

**Key name:** Value name  
**Command:** Command to be ran when registry is used  
**Registry key:** Location where registry key will be created  
**Hidden:** Will prepend a null byte to the key name; throws errors in regedit  
**Cleanup:** Removes created key

Cleanup requires the key name and registry key (location).  
UserInitMprLogonScript: Automatically sets 'Key name'and 'Registry key'.

___

### Scheduled Task COM Hijack
#### Description

Hijacks a scheduled task's COM handler. Creates a registry key at HKCU:\\Software\\Classes\\CLSID\\<CLSID>\\InprocServer32 which points to a DLL.

#### Parameters

**Class ID:** The CLSID that corresponds to the task's COM handler CLSID  
**DLL path:** Path to DLL that is to be loaded  
**Cleanup:** Removes created key

___

## Drivers
### DisableDSE

| Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: |
| 4 | Yes | Can potentially BSOD target system |

#### Description

Loads a vulnerable signed driver with arbitrary kernel memory read/write (NalDrv/iqvm64.sys). Changes the ntoskrnl.exe `g_CiEnabled` or CI.dll `g_CiOptions` flag to disable Driver Signature Enforcement (DSE).  
Loads a non-signed driver (Interceptor/Interceptor.sys), then restores the DSE flag values. Both the signed driver and non-signed driver are written to disk.

| Driver | MD5 checksum |
| :---: | :---: |
| iqvm64.sys | 1898ceda3247213c084f43637ef163b3 |
| Interceptor.sys | 508c8943359717cfa0c77b61ebea2118 |

#### Parameters

**Vulnerable driver location:** Location of vulnerable signed driver in binary form on disk  
**Malicious driver location:** Location of the malicious non-signed driver in binary form on disk  
**Vulnerable driver name:** name used to create the registry key '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\<name>'  
**Vulnerable driver device name:** name used to contact the driver '\\DosDevices\\<name>'  
**Malicious driver name:** name used to create the registry key '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\<name>'  
**Malicious driver device name:** name used to contact the driver '\\DosDevices\\<name>'  
**Target path:** temporary path to write the vulnerable and malicious driver files to

___

### UnloadDriver

| Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: |
| 5 | Yes | - |

#### Description

Unloads a driver on the target using the provided registry key and deletes the binary from disk at the specified path.

#### Parameters

**Driver registry key:** registry key used to unload driver '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\<name>'  
**Driver installation path:** location of driver on disk

___

### Intercept

| Reliability (0-5) | Elevated | Remarks |
| :---: | :---: | :---: |
| 4 | No | Can potentially BSOD target system |

#### Description

**Information:** Query the Interceptor driver  
**Hook:** Hook the target driver's major functions (IRP)  
**Unhook:** Restore the target driver's major functions  
**Patch:** Patch the target kernel callbacks  
**Restore:** Restore the target kernel callbacks

#### Parameters: Information

**Vendors:** display supported vendors  
**Modules:** query all loaded drivers  
**Hooked modules:** display all hooked drivers  
**Callbacks:** query all registered callbacks

#### Parameters: Hook

**Index:** hook a driver by index (see: information - modules)  
**Name:** hook a driver by device name (\\Device\\Name)  
**Values:** comma separated list of indexes (conditional)  
**Name:** device name of the target driver (conditional)

Values are required when 'Index' is selected. Name is required when 'Name' is selected.

#### Parameters: Unhook

**Index:** unhook a driver by index (see: information - hooked modules)  
**All:** unhook all hooked drivers  
**Values:** comma separated list of indexes (conditional)

Values is required when 'Index' is selected.

#### Parameters: Patch

**Vendor:** patch all callbacks associated with vendor module(s)  
**Module:** patch all callbacks associated with module(s)  
**Process:** patch process callback(s)  
**Thread:** patch thread callback(s)  
**Image:** patch image callback(s)  
**Registry:** patch registry callback(s)  
**Object process:** patch object process callbac(s)  
**Object thread:** patch object thread callback(s)  
**Values:** comma separated list of indexes (see: information - callbacks) (conditional)  
**Name:** comma separated list of module names or single vendor name (see: information - vendors) (conditional)

Values is required when 'process', 'thread', 'image', 'registry', 'object process' or 'object thread' is selected. Name is required when 'vendor' or 'module' is selected.

#### Parameters: Restore

**Vendor:** restore all callbacks associated with vendor module(s)  
**Module:** restore all callbacks associated with module(s)  
**Process:** restore process callback(s)  
**Thread:** restore thread callback(s)  
**Image:** restore image callback(s)  
**Registry:** restore registry callback(s)  
**Object process:** restore object process callbac(s)  
**Object thread:** restore object thread callback(s)  
**All:** restore all callbacks  
**Values:** comma separated list of indexes (see: information - callbacks) (conditional)  
**Name:** comma separated list of module names or single vendor name (see: information - vendors) (conditional)

Values is required when 'process', 'thread', 'image', 'registry', 'object process' or 'object thread' is selected. Name is required when 'vendor' or 'module' is selected.

___
