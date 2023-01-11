---
title: "Windows Forensics Investigation"
classes: wide
header:
  teaser: /assets/images/forensic-investigation/forensics.jpg
ribbon: DodgerBlue
description: "Notes of study for Windows OS forensics ..."
categories:
  - Forensic investigation
toc: true
---
# Registry Analysis 

## Core knowledge

Hives contain Keys and values :
- Keys are folders.
- SubKeys are folders inside folders.
- Values are data stored in the Keys.
Hives contain info about :
- Hardware.
- User settings.
- Software.
- System configuration.

Keys have last write times and MRUlist "Most recent used"

## Where to find Hives

`system` hives HKLM are in 
"%WinDir%\System32\Config" are :
	
	SAM
	SECURITY
	SYSTEM
	SOFTWARE
	DEFAULT

"%WinDir%\appcompat\Programs" is :

	AMCACHE.hve

	There is also another place for storing the first-mentioned hives in 
	"%WinDir%\System32\Config\RegBack" 
	which is mainly used as a backup

`User` hives HKCU :
each individual user has a registry hive that can show specific details as to user activity on a machine which is a really important aspect of computer forensics.
you can find it at 
"C:\Users\%USERNAME%\"

	NOTE: the artifacts may not be recorded immediately to the registry.
	They may be stored for some time in a .LOG file then push all of the changes that happened together.
	this is used to minimize the IO operations to the registry.

## Collecting User Information

	Username
	Relative Identifier "RID"
	User Login Information
	Group Information

In `"SAM\Domains\Account\Users\"` you can find

	Username
	RID
	Last Login
	Last Failed Login
	Logon Count
	Password Policy
	Account Creation Time

Microsoft portal accounts don't increase the login Count

## Examining System Configuration 

	Identify Microsoft OS Version
	Current Control Set
	Computer Name
	Time Zone of the Machine
	Network Interfaces
	Historical Networks
	Network Types
	System Auto Start Programs
	Shares of the System
	Number of Times Shutdown was Initiated
	Last Shutdown Time

Identify Microsoft OS Version :

	SOFTWARE\Microsoft\Windows NT\CurrentVersion
"installdate" key is updated in many situations like resetting the machine...etc

Current Control Set :

	SYSTEM\Select
Points to the control sets of the machine.

Computer Name :

	SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName

Time Zone of the Machine:

	SYSTEM\CurrentControlSet\Control\TimeZoneInformation

NTFS Last Access Time ON/OFF? :

	SYSTEM\CurrentControlSet\Control\FileSystem

Network Interfaces :

	SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces

Historical Networks :

	SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
	SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
	SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache

Network Profiles :
Network Types :

	SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Prifiles

Find the GUID from Historical Networks
- nametype value = 0x47 = wireless
- nametype value = 0x06 = wired
- nametype value = 0x17 = broadband(3G)

"times there are stored in local time"



System Auto Start Programs :
 	
	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Run
	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\RunOnce
	SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
	SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
	SYSTEM\CurrentControlSet\Services

if start = 0x2 means start at boot.

Shares of the System :

	SYSTEM\CurrentControlSet\Services\lanmanserver\Shares\

Last Shutdown Time :

	SYSTEM\CurrentControlSet\Control\Windows

## Analyzing Documents Activity

Search History :

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
	
Typed PAths :

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

File opening :

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

Office file opening:

	 NTUSER.DAT\software\Microsoft\Office\VERSION
	 NTUSER.DAT\software\Microsoft\Office\VERSION\User MRU\LiveID_####\File MRU

Open Save MRU :
        #files chosen from DialogBox

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidMRU

Last Visited :
	#files chosen from DialogBox

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidMRU

## Program Execution Artifacts

Command line :
	
	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

GUI Program Execution :

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Search\RecentApps
	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
	SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache
	Amcache.hve\Root\File\{Volume GUID}\#######
	SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}
	SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}

GUIDs :
CEBFF5CD... Executable File Execution
F4E57C4B... Shortcut File Execution

# Shell Items

Data or file that has information to access another file is known as a Shell Item.
Shell Items always have the same headers. {4C 00 00 00 ...}


## Shortcut Files 


Any non-executable file opened in windows generates a minimum of TWO LNK files in the path "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent"
- Target file.
- Parent Folder of the target file.

        Note:
        Data created for the shortcut there points to the first time the file opened.
        Data modified for the shortcut there points to the last time the file opened.
        if two files have the same name in the system that will generate one shortcut.

        If the time modified of the LNK is before the time created that is likely to be copied.

opening Links from (Run dialog, lnk file, or app) the link will generate an LNK file also.

## Jump Lists 

Jump lists are those things that are lastly opened by specific applications made to make you quickly access things that you frequently access or the last things you accessed.

you can find a hidden folder In 

    "C:\Users\Amras\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
    "C:\Users\Amras\AppData\Roaming\Microsoft\Windows\Recent\CustomeDestinations"
This file contains a large number of databases that hold this information.

The start of the file name is an ID which is universal for each app.

    Note: Structured storage viewer tool can parse them.

## Shellbags 

Contains user-specific Windows OS folder and viewing preferences to Windows Explorer

Found in :
    
    Explorer Access:
    USRCLASS.DAT\Local Settings\Software\Windows\Shell\Bags
    USRCLASS.DAT\Local Settings\Software\Windows\Shell\BagMRU
    Desktop Access:
    NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
    NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU    