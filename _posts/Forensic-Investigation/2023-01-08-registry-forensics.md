---
title: "Registry Investigation"
classes: wide
header:
  teaser: /assets/images/forensic-investigation/registery.png
ribbon: DodgerBlue
description: "Important Keys to look at for registery analysis ..."
categories:
  - Forensic investigation
toc: true
---
# Registry Analysis 

## Core knowledge

Hives contains Keys and values :
- Keys are folders.
- SubKeys are folders inside folders.
- Values are data stored in the Keys.
Hives contains info about :
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

	There is also another place for storing the first mentioned hives in 
	"%WinDir%\System32\Config\RegBack" 
	which is mainly used as backup

`User` hives HKCU :
each individual user has a registry hive that can show specific details as to user activity on a machine which is realy important aspects of computer forensics.
you can find it at 
"C:\Users\%USERNAME%\"

	NOTE : the artifacts may not recorded emediatly to the registry.
	They may be stored for some time in a .LOG file then push all of the changes that happend togather.
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
	Numper of Times Shutdown was Initiated
	Last Shutdown Time

Identify Microsoft OS Version :

	SOFTWARE\Microsoft\Windows NT\CurrentVersion
"installdate" key is apdated in many situation like restting the machine...etc

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

"times there are stored in localtime"



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

File openning :

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

Office file openning :

	 NTUSER.DAT\software\Microsoft\Office\VERSION
	 NTUSER.DAT\software\Microsoft\Office\VERSION\User MRU\LiveID_####\File MRU

Open Save MRU :
        #files chosed from DialogBox

	NTUSER.DAT\software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidMRU

Last Visited :
	#files chosed from DialogBox

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

GUIDs -> CEBFF5CD... Executable File Execution

      -> F4E57C4B... Shortcut File Execution
