---
title:  "Pikabot Loader Detailed Analysis"
date:   2024-02-25 05:00:00 +0300
header:
  teaser: "/assets/images/pikabot/hash.png"
categories: 
  - malware
tags:
  - dfir
  - malware
  - blueteam
  - debugging
  - threat-hunting
  - investigations
  - general
---
# introduction

`Pikabot`, a modular backdoor first discovered in 2023, employs anti-analysis techniques within its loader component. The core component, responsible for most malicious functionalities, receives commands from a command-and-control server, allowing for arbitrary code injection.

As the loader part is the one that implements all the Anti-Analysis Techniques to evade analysis, and also it's the part that we will be looking for in any compromised system, we are going to analyze the loader part of this malware.

# Sample OverView

We are working on a `Pikabot` sample with the following hashes:

|SHA256:|30db7abf0363af237d64843c95e9bf79f35919e6297f3d5d13acd3a89ab1443f|
|-------|-------------------------------------------------------|
|MD5:   |f582fa17542fc2b5257f8d3e50eb6231|
|

you can download it from [Malware Bazzar](https://bazaar.abuse.ch/sample/30db7abf0363af237d64843c95e9bf79f35919e6297f3d5d13acd3a89ab1443f/)

The sample looks packed as we have a relatively high entropy.

![Error Loading](/assets/images/pikabot/die.png)

So we can use a service like unpacme to unpack it, you can find the result [here](https://www.unpac.me/results/3c7fc1b6-62b1-4ea9-86a5-06b0a850a16d#/)

Now we are dealing with unpacked DLL with the following hashes:

|SHA256:|6f210d1002f0034dc842bbe923cd37e228805386b7c925a52161dc1f17f8c45d|
|-------|-------------------------------------------------------|
|MD5:   |4031aff3ed17bf49d8bd3d8f0d7cb24f|
|



# Loader Analysis

The Loader Code is considered somewhat a small code, we can get throw its code and techniques quickly.

We can see that the malware contains some `Junk Code` that doesn't make sense at the start, just pushing some value at the stack and never touching it.

![Error Loading](/assets/images/pikabot/junk.png)

The malware implements a series of checks after each function execution, although some functions will always return the same value, this is an obfuscation technique used to make the analysis harder.

Let's get to the first function, which is used to resolve the address of `GetProcAddress` and `LoadLibrary`, using `API Hashing` Technique, those are the only two APIs that are resolved by hashes, then the rest of the APIs is resolved using them.

![Error Loading](/assets/images/pikabot/hash.png)


Through all the other functions, we can find several operations happening on stackstrings, which indicate that the sample uses `Encrypted Stack Strings" to hide its strings, those strings decrypted are mostly the APIs to be resolved, and a little of other stuff.

![Error Loading](/assets/images/pikabot/dec.png)

Through the code we can find it's using different keys and different operations, this may make the automatic extraction of the strings harder.

An easy way of doing that is by using a debugger.

![Error Loading](/assets/images/pikabot/debug.png)

We can see the malware uses an Anti-Debugging technique by using "INT 0x2D" instruction, this instruction is used to raise an exception for breakpoint, If we are in the debugger no exception will be generated, before that the malware registers an exception handler, this way the attacker know that we are in a debugger if the Custom Handler didn't execute.

![Error Loading](/assets/images/pikabot/exc.png)

To continue our analysis easily I wrote this small template of code to decode these stack strings, just copy the stack variables in the code and change the key and the operation variables.

```py

v29 = 0xE9E7DFCC;
v30 = 0xDFD0DFF0;
v31 = 0xECE9EEDD;
v32 = 0xF2BFDEDF;
v33 = 0xEEEADFDD;
v34 = 0xC2E8E9E3;
v35 = 0xE6DEE8DB;
v36 = 0xECDF;

key = 0x7A

def operation(byte):
    return max(0, byte - key)  

data = [
    v29 & 0xFF, (v29 >> 8) & 0xFF, (v29 >> 16) & 0xFF, (v29 >> 24) & 0xFF,
    v30 & 0xFF, (v30 >> 8) & 0xFF, (v30 >> 16) & 0xFF, (v30 >> 24) & 0xFF,
    v31 & 0xFF, (v31 >> 8) & 0xFF, (v31 >> 16) & 0xFF, (v31 >> 24) & 0xFF,
    v32 & 0xFF, (v32 >> 8) & 0xFF, (v32 >> 16) & 0xFF, (v32 >> 24) & 0xFF,
    v33 & 0xFF, (v33 >> 8) & 0xFF, (v33 >> 16) & 0xFF, (v33 >> 24) & 0xFF,
    v34 & 0xFF, (v34 >> 8) & 0xFF, (v34 >> 16) & 0xFF, (v34 >> 24) & 0xFF,
    v35 & 0xFF, (v35 >> 8) & 0xFF, (v35 >> 16) & 0xFF, (v35 >> 24) & 0xFF,
    v36 & 0xFF, (v36 >> 8) & 0xFF, (v36 >> 16) & 0xFF, (v36 >> 24) & 0xFF,
]

result = [operation(byte) for byte in data]

if len(result) == 1:
    print(result[0])  
elif all(isinstance(byte, int) for byte in result):
    print("".join([chr(byte) for byte in result]))  
else:
    print(result)  
```

![Error Loading](/assets/images/pikabot/scr.png)
![Error Loading](/assets/images/pikabot/try.png)

we can also use emulation, but that is what came to my mind first.

The next function is doing the same Anti-Debug Technique this time using `_debugbreak`.

![Error Loading](/assets/images/pikabot/break.png)

After that, a series of debug checks with simple techniques, by Checking the BeingDebugged member of the PEB, checking if a remote debugger is attached, and checking again the BeingDebugged flag but using an API this time not manual parsing.

![Error Loading](/assets/images/pikabot/checks.png)

Another Anti-Sandbox technique is using `Beep` Api which is often passed by sandboxes and AVs to save time during the behavioral analysis as it takes a large time delay to finish execution.

![Error Loading](/assets/images/pikabot/beep.png)

Another Anti-Debugging check used also is `NtGlobalFlag` check, this value should be zero if no debugger is attached.

![Error Loading](/assets/images/pikabot/glob.png)

We can find another good anti-debugging technique also, which is using `OutputDebugString`, but who this work?!

the malware starts by setting an error code and then calling "OutputDebugString" which is used to send messages to the debugger console, if no debugger is attached this will result in a specific error code, the malware then checks if the last error code isn't changed, that means no error resulted from "OutputDebugString" and it's running in a debugger.

![Error Loading](/assets/images/pikabot/deb.png)

Also, I noticed that the malware uses Anti-Sandbox technique by enumerating files or environment variables that don't exist, and if something is returned that will be an indicator of a sandbox, as sandboxes more often emulate everything the analyzed sample wants to make it execute as much code as possible but some malwares like this uses that feature against them.  

![Error Loading](/assets/images/pikabot/random.png)

Also, we can find the malware uses another Anti-Analysis technique by using `GetWriteWatch` API to watch if the memory content is modified more than expected.

![Error Loading](/assets/images/pikabot/watch.png)

After All these checks, we can find the sample uses `Remote Injection` to run a new process and inject the final payload into that process.

![Error Loading](/assets/images/pikabot/create.png)

In our case this process is "dllhost.exe", then "WriteProcessMemory" is used to inject code.

![Error Loading](/assets/images/pikabot/write.png)

At the end the injected code has the core functionality of the Malware can be simply extracted by bypassing the previously mentioned techniques then putting a breakpoint at "WriteProcessMemory" and extracting the payload that will be injected.

# Summery

In this blog post, we analyzed the new version of `Pikabot` loader which has many Anti-Analysis techniques like:

- JunkCode
- API Hashing
- Encrypted Stack Strings
- INT 0x2D instruction
- OutputDebugString Error
- Memory Write Watch

Author: `Amr Ashraf`