---
title: "Linux Forensics In Depth"
classes: wide
header:
  teaser: /assets/images/forensic-investigation/Linux_forensics/hier.png
ribbon: DodgerBlue
description: "investigating Linux Disk Image In Depth"
categories:
  - Forensic investigation
toc: true
---

# OverView 

Linux is a big target as almost every server is running some sort of Linux, In this blog post I will try to cover details as possible but also I will expect the reader to have some knowledge of using Linux, I will start with simple topics and move towards advanced ones.

Some of the content in this post is copied from the references as they described it in the best way.

# Linux Directory Layout

I can't speak about linux forensics with out mentioning the directory layout for it, So if you are comfortable with it pass this section.

![Error](/assets/images/forensic-investigation/Linux_forensics/layout.png)

There is no stander specification forced to follow for every folder and what should be stored there so every distripution document it's file structure in `hier` man page, but always top directories remain the same.

![Error](/assets/images/forensic-investigation/Linux_forensics/hier.png)

*/boot/ and efi*

These directories contains files related to boot process configurations like kernel parameters and previous linux kernels and [initial ramfs](https://en.wikipedia.org/wiki/Initial_ramdisk), more details comes later.

*/etc/*

System wide configurations are stored here and most of them are stored in plaintext format, looking at modification and creation timestamp here is good in any forensics investigation, more details comes later.

*/srv/*

this folder contains servers data like FTP, HTTP...

*/tmp/*

This folder stores temporary data and based on the distripution configuration it may be deleted periodically or on boot.

*/run/*
On a running system, this directory contains runtime information like PID and lock files, systemd
runtime configuration, and more.
In a forensic image it will likly be empty.

*/home/ and /root/*

This is home folder for any user in the system and the root user folder also.

*/bin/, /sbin/, /usr/bin/, and /usr/sbin/*

These are the folders storing executables in the system, In general half of them is just a symlink for the other "/bin/ -> /usr/bin" and "/sbin/ -> /usr/sbin/"

*/lib/ and /usr/lib/*

these directory contains libraries needed by applications to run.

*/usr/*

The /usr/ directory contains the bulk of the system’s static read-only data. This includes binaries, libraries, documentation, and more.

*/var/* 

The /var/ directory contains system data that is changing (variable) and
usually persistent across reboots. The subdirectories below /var/ are
especially interesting from a forensics perspective because they contain
logs, cache, historical data, persistent temporary files, the mail and
printing subsystems, and much more.

*/dev/, /sys/, and /proc/*

These directories provide representations of devices or kernel data structures but the contents don’t actually exist on a normal filesystem. When examining a forensic image, these directories will
likely be empty.

*/media/*

The /media/ directory is intended to hold dynamically created mount points for mounting external removable storage, such as CDROMs or USB drives. When examining a forensic image, this directory will likely be empty.
References to /media/ in logs, filesystem metadata, or other persistent data may provide information about user attached (mounted) external storage devices.

*/opt/*

The /opt/ directory contains add-on packages, which typically are grouped by vendor name or package name. These packages may create a self-contained directory tree to organize their own files (for example, bin/, etc/, and other common subdirectories).

*/lost+found/*

A /lost+found/ directory may exist on the root of every filesystem. If a filesystem repair is run (using the fsck command) and a file is found without a parent directory, that file (sometimes called an orphan) is placed in the /lost+found/ directory where it can be recovered. Such files
don’t have their original names because the directory that contained the filename is unknown or missing.

# the "." files

Applications saves It's cashed and history and whatever the developer decided to store in hidden files or directories in the system, these hidden contents start with ".", there is no specifications for forcing the developer to store it in a specific place.

Here is some examples on my own system.

![Error](/assets/images/forensic-investigation/Linux_forensics/hidden.png)

here we can see history of "bash, python, php, gdb, vim, less, wget" and there is others also.
Looking at one of them like "python_history" we can see alist of all the executed commands in python shell.

![Error](/assets/images/forensic-investigation/Linux_forensics/py.png)

as you can see you can find that I was doing some binary exploitation work and that is right you managed to get evidence of user activity, and you can construct more by looking in these files, but that is confidential for me but you got the point.

another intersting hidden folder is ".ssh" folder where you can look for hashed names on "known_hosts", you can't unhash them but you can find the deviations by hashing the known ones and comparing.

although there is no standerd place to store this kind of files, there is a specification for best practice recommended,The specification defines environment variables and default locations that operating systems and applications may use instead of creating their own proprietary files and directories in the user’s home directory.
These location environment variables and associated default locations are:

- Data files: $XDG_DATA_HOME or default ~/.local/share/*
- Configuration files: $XDG_CONFIG_HOME or default ~/.config/*
- Non-essential cache data: $XDG_CACHE_HOME or default ~/.cache
- Runtime files: $XDG_RUNTIME_DIR or typically /run/user/UID (where UID is the numeric ID of the user)

These Data, Configuration and Cache ddirectories will contain amount of usful information for forensics investigation.

one small example of data that can be found there is in "~/.local/share/" is `*.xbel` file which contains recently used files, Trash which is like a recycle bin, alot of evidence resides there so make sure to take time reviewing it, I will not mention every one of them as they are self explanatory when you look at theire names or content like configurations and logs for non standerd applications.

# Crashes & Dumps

Crash Dumps can provide a significant amount of evidence in forensics investigation as it saves the content of the memory in the time of a crash that can give us alot of information if a process was under attack or some one was trying to exploit it, we can get a list of crashes and theire time stamp using the followig command.

```sh
coredumpctl
```

![Error](/assets/images/forensic-investigation/Linux_forensics/crash.png)

As you can see here I was trying to exploit a a stack overflow in a binary in the machine and that gets recorded, although some times like in the picture the Dump it self maybe missing.

where logs and crash files is saved is different from distripution to another so You need to conduct a small searh of where this files resides in your distripution.

# Linux Logs

*/var/log/* is not the only place where logs are stored but definetly it's the most important one, the logs file stored there varies between different distriputions but here some geberal ones.

- auth.log or /var/log/secure: Logs related to authentication and security, including login attempts, authentication failures, and security-related events.

- syslog or /var/log/messages: General system logs that capture a wide range of system events, including kernel messages and system daemon messages.

- kern.log: Kernel-specific logs that contain messages related to the Linux kernel.

- dmesg: Kernel boot messages and hardware-related messages.

- boot.log: Logs related to the system boot process.

- cron: Logs for the cron scheduling daemon, which records scheduled job executions.

- mail.log or /var/log/maillog: Logs for mail-related services, such as Sendmail or Postfix.

- httpd/ or /var/log/apache2/: Logs for the Apache web server.

- nginx/: Logs for the Nginx web server.

- mysql/ or /var/log/mariadb/: Logs for the MySQL or MariaDB database server.

- audit/: Audit logs that record security events and access control-related information.

- auth.log: SSH login logs.

- wtmp and btmp: Logs that track login and logout events. wtmp records successful logins, while btmp records failed login attempts.

- lastlog: Records the last login information for each user.

- ufw.log: Logs for the Uncomplicated Firewall (UFW) on Ubuntu systems.

- secure: Additional security-related logs, often found on CentOS and Red Hat-based systems.

- auth.log: Authentication logs on Debian and Ubuntu systems.

- alternatives.log: Logs related to the alternatives system, which manages symbolic links for system commands and libraries.


Logs in Linux have the following severities.

- 0 emergency (emerg or panic): system is unusable
- 1 alert (alert): action must be taken immediately
- 2 critical (crit): critical conditions
- 3 error (err): error conditions
- 4 warning (warn): warning conditions
- 5 notice (notice): normal but significant condition
- 6 informational (info): informational messages
- 7 debug (debug): debug-level messages

you can find `rsyslog` configuration in 

- /etc/rsyslog.conf
- /etc/rsyslog.d/\*.conf

where you can see in the first one where the logs are stored localy the "@" means stored in another place over network.

- Programs can generate messages with any facility and severity they want.
- Syslog messages sent over a network are stateless, unencrypted, and based on UDP, which means they can be spoofed or modified in transit.
- Syslog does not detect or manage dropped packets. If too many messages are sent or the network is unstable, some messages maygo missing, and logs can be incomplete.
- Text-based logfiles can be maliciously manipulated or deleted.

These are all problems with the legacy syslog way, so another entire log system is built to overcome this proclems which is `Systemd Journal`.

the Journal system is well documented in man page `systemd-journald`. 

you can view a .journal file content using "journalctl --file filename"
(Customized search and regular expression stuff can be done to enhance your search)

There is also non stander logs that applications and servers can create its own log files to store it's logs, these also can provide a huge amount of foresically important data that depends on the nature of the case.

A note to add here at the end that you can add custome log role to log on your system using `auditd` service.

To add a custom rule to log specific events in Ubuntu's logging system, you can use the Audit framework (Auditd). Auditd allows you to define rules that specify which system events you want to monitor and log. Here's a general process for adding a rule:

- Edit Audit Rules Configuration:

Open the audit rules configuration file for editing using a text editor like "nano" or "vim." This file is typically located at "/etc/audit/rules.d/audit.rules":

```sh
sudo nano /etc/audit/rules.d/audit.rules
```

If the file doesn't exist, you can create it.

- Add a Custom Rule:

In the audit rules file, you can define custom audit rules to specify what events to log. The rules follow a specific format. For example, to log all file reads in the "/etc/" directory, you can add the following rule:

```sh
-a always,exit -F dir=/etc/ -F perm=r -k etc_read
```
-a always,exit: This part of the rule specifies that the event should be logged when it exits (e.g., when a process finishes reading a file).
-F dir=/etc/: This part specifies the directory to monitor ("/etc/").
-F perm=r: This part specifies the permission ("r" for read) to monitor.
-k etc_read: This part specifies a unique key for the rule.
You can customize the rule according to your needs, specifying the events, directories, permissions, and keys that match your requirements.

- Save and Close the File:

Save your changes in the editor and exit.

- Reload Audit Rules:

After adding or modifying audit rules, you need to reload the audit configuration to apply the changes:

```sh
sudo service auditd reload
```

This will activate the new audit rule.

- View Audit Logs:

The audit logs are typically stored in /var/log/audit/audit.log. You can view the logs using a tool like aureport or ausearch, or simply by examining the log file itself. For example, to view all events related to the "etc_read" key defined in the example rule:

```sh
ausearch -k etc_read
```

This command will display all events matching the specified key.

Remember that monitoring too many events or setting overly broad rules can generate a large volume of logs. Be specific with your rules to capture the events that are relevant to your monitoring needs while avoiding excessive noise. Additionally, regularly review and manage your audit logs to ensure they do not consume excessive disk space.

# Software Installation

The initial state of the distripution after installation can be found in `/var/log/installer` here you can see different logs about installed drivers and packeges and alot of others.  

Let's start discussing `*.deb` files which are package installers this is actually a compressed file containing three components

- `debian-binary` A file containing the package format version string
- `control` A compressed archive with scripts/metadata about the package
- `data` A compressed archive containing the files to be installed

From a forensics perspective, we can ask many questions related to
package management, such as the following:

- What packages are currently installed, and which versions?
- Who installed them, when, and how?
- Which packages were upgraded and when?
- Which packages were removed and when?
- Which repositories were used?
- Can we confirm the integrity of the packages?
- What logs, databases, and cached data can be analyzed?
- Given a particular file on the filesystem, to which package does it
- belong?
- What other timestamps are relevant?

We will focus on one package manager `apt` but the concept remains the same for all of them.

we can get a list of installed packages in `/var/lib/dpkg/status` file

here are some files to look for artifacts in:

- /var/log/dpkg.log dpkg activity, including changes to package status (install, remove, upgrade, and so on)
- /var/log/apt/history.log Start/end times of apt commands and which user ran them
- /var/log/apt/term.log Start/end times of apt command output (stdout) /var/log/apt/eipp.log.* Logs the current state of the External Installation Planner Protocol (EIPP), a system that manages dependency ordering
- /var/log/aptitude Aptitude actions that were run
- /var/log/unattended-upgrades/* Logs from automated/unattended upgrades
- /etc/dpkg/ Configuration information for dpkg is stored here
- /etc/apt/ Configuration information for apt and the sources.list and sources.list.d/* files. These files are interesting because they define the configured external repositories for a particular release is stored here
- /var/lib/dpkg/info/ directory contains several files for each installed package (this is the metadata from the DEB files). This information includes the file list (\*.list), cryptographic hashes (\*.md5sums), preinstall/postinstall and remove scripts, and more.
- /var/cache/apt/archives/ directory contains *.deb files that have been downloaded in the past.
- /var/cache/debconf/ directory is a central location for package configuration information and templates.

- /var/lib/snapd/snaps/ Contains downloaded snaps
- ~/.local/lib/python*/ site-packages and ~/usr/lib/python*/ site-packages are where pip installed packeges saved.

# Login & User Interaction Forensics

- /var/log/wtmp History of successful logins and logouts(can be parsed using "last -f filename")
- /var/log/btmp History of failed login attempts(can be parsed using "lastb -f filename")
- /var/log/lastlog Most recent user logins
- /var/run/utmp Current users logged in (only on running systems)

An Interesting place to look at a forensics investigation is initialization scripts

- /etc/profile
- /etc/profile.d/*
- ~/.bash_profile
- /etc/bash.bashrc
- ~/.bashrc

the profile file runs once at the first shell and "\*rc" files runs every time you open a shell.

- /etc/bash.bash_logout
- ~/.bash_logout

these files also run one on exit and logout.

Environment variables are also a good place to look where you can find more about the user's default editor which may tell you where to look for more evidence and customized environment variables which can give you good hints.

here are some places to look at defult environment variables at login.

- /etc/security/pam_env.conf
- /etc/environment
- /etc/environment.d/*.conf
- /usr/lib/environment.d/\*.conf
- ~/.config/environment.d/\*.conf

you can look at "HIST*" environment variables where the shell history is configured that will tell you about where the shell history stored and how it's configured.

Another note here is that command history of a shell is written only after the shell exits.

Also, note that the newly written bash history dropped to the disk is written to a new inode and the old one is still there in the disk unallocated so you can find old bash history files using carving.

Windows manegers also have some startup "\*.desktop" files have the applications to start at startup.

- /etc/xdg/autostart/*
- ~/.config/autostart/*

For the Desktop setting, there is a database called `dconf` which is much like the Windows registry where the data is stored in hierarchy key-value pairs, I will give a look to "GNOME" desktop manager.

[here](https://github.com/chbarts/gvdb/) you can find a tool to parse this database content.

the "dconf" files can be found in "~/.config/dconf/" and "/etc/dconf/db/" as example you can look at "user" database where user setting can be found.

There is alot of `Clipboard` manegers out there that stores from 5-20 history copied data but as there is alot out there you will need to search for where your maneger stores this data.

Recent Documents and favourites in linux are kept track of for every user in linux in different places like...

- .local/share/recently-used.xbel
- .local/user-places.xbel
- .local/share/Recent Documents/

Search history also is kept track of for every user each desktop manger has it's own way, for example in GNOME search is saved to "~/.cache/tracker3/files" as sqlite databases.

# Cheat sheet
here are some good places to look for persistence

- /etc/cron*/
- /etc/incron.d/*
- /etc/init.d/*
- /etc/rc*.d/*
- /etc/systemd/system/*
- /etc/update.d/*
- /var/spool/cron/*
- /var/spool/incron/*
- /var/run/motd.d/*

- /etc/passwd
- /etc/sudoers
- ~/.ssh/authorized_keys
- ~/.bashrc 



<details>
<summary>Click to expand Linux evidence files cheat sheet</summary>

- /

- / Top or root directory of the system; all additional filesystems or pseudo-filesystems are mounted on a subdirectory within this tree.

- ./ Every directory contains a dot subdirectory that refers to itself.

- ../ Every directory contains a double-dot subdirectory that refers to its 
parent directory.
- /bin/ Contains executable files; often symlinked to /usr/bin/.

- /boot/ Directory containing bootloader files (grub, and so on) and possibly the EFI mount point.

- /cdrom/ Traditional generic mount point for temporarily mounted
removable media such as CD or DVD discs; likely empty on a forensic image.

- /desktopfs-pkgs.txt, /rootfs-pkgs.txt Manjaro initial package install lists.

- /dev/ Location of device files, usually dynamically created (and removed) by the udev daemon; likely empty on a forensic image.

- /etc/ Directory for storing system-wide configuration data; helps reconstruct how a system was configured.

- /home/ The home directories of normal users on the system; contains the most evidence of user activity.

- /initrd.img Symlink to an initial RAM disk image (usually from /boot/); may also have initrd.img.old if initrd was updated.

- /lib32/ Contains 32-bit compatible libraries and executables; may be symlinked to /usr/lib32/.

- /lib64/ Contains 64-bit compatible libraries; may be symlinked to /usr/lib64/.

- /lib/ Contains libraries and executables; often symlinked to /usr/lib/.

- /libx32/ Contains compatible libraries and executables for the x32 ABI (64-bit instructions, 32-bit pointers); may be symlinked to /usr/libx32/.

- /lost+found/ Directory for orphan files (files without a parent directory)
found during filesystem repair. It may exist at the root of any mounted filesystem.

- /media/ Directory for dynamically created mount points for removable media (USB sticks, SD cards, CD/DVD discs, and so on); likely empty on a forensic image.

- /mnt/ Traditional generic mount point for temporarily mounted filesystems; likely empty on a forensic image.

- /opt/ Directory containing “optional” or add-on software.

- /proc/ Mount point for a pseudo-filesystem interface for information about running processes; likely empty on a forensic image.

- /root/ The root user’s home directory (deliberately located outside /home/).

- /run/ Mount point for a tmpfs filesystem with runtime data; may be symlinked with /var/run/; likely empty on a forensic image.

- /sbin/ Contains executable files; often symlinked to /usr/sbin/ or /usr/bin (if bin and sbin have been merged)

- /snap/ Directory for Snap software package symlinks and mount points; may be symlinked to /var/lib/snapd/snap.

- /srv/ Directory used for storing served content (HTTP, FTP, TFTP, and so on).

- /swapfile A file-based alternative to a separate swap partition; may contain fragments of memory from the last time the system was running or a hibernation memory image.

- /sys/ Mount point for a pseudo-filesystem interface to the running kernel; likely empty on a forensic image.

- /tmp/ Mount point for a tmpfs filesystem for temporary files (lost on reboot); likely empty on a forensic image.

- /usr/ Intended to be a directory of read-only files that can be shared by multiple systems; today mostly contains static files from installed packages.

- /var/ Directory for storing variable system and application data; normally persistent across reboots and contains evidence stored in logfiles.

- /vmlinuz Symlink to a kernel image (usually from /boot/); may also have vmlinuz.old if the kernel was updated.

*/boot/*

- /boot/amd-ucode.img AMD CPU microcode updates (archive containing files).

- /boot/cmdline.txt Kernel parameters on Raspberry Pi.

- /boot/config-* Kernel configuration.

- /boot/initramfs.* Initial RAM disk (archive containing files).

- /boot/initrd.* Initial RAM disk (archive containing files).

- /boot/intel-ucode.img Intel CPU microcode updates (archive containing files).

- /boot/System.map-* Kernel symbol table.

- /boot/vmlinuz-* Linux kernel image file.

*/boot/grub/*

- /boot/grub/custom.cfg Additional GRUB customization.

- /boot/grub/grub.cfg GRUB configuration file (can also be in the EFI/ directory).

- /boot/grub/grubenv GRUB environment block, 1024 bytes, fixed size.

- /boot/grub/i386-pc/ 32-bit GRUB modules.

- /boot/grub/, /boot/grub2/ GRUB directory for bootloader files.

- /boot/grub/x86_64-efi/ 64-bit GRUB modules.

- /boot/loader/

- /boot/loader/ Systemd’s bootloader (systemd-boot, formerly gummiboot).

- /boot/loader/loader.conf Overall systemd-boot configuration.

- /boot/loader/entries/\*.conf Boot entry configuration files.

*EFI/*

- EFI/ EFI system partition (ESP), FAT filesystem; typically mounted on /boot/efi/ or /efi/.

- EFI/BOOT/BOOT64.EFI, EFI/BOOT/BOOTX64.EFI A common default 64-bit EFI bootloader.

- EFI/BOOT/BOOTIA32.EFI A common default 32-bit EFI bootloader.

- EFI/fedora/, EFI/ubuntu/, EFI/debian/ Examples of distro-specific EFI directories.

- EFI/\*/grubx64.efi GRUB’s EFI bootloader.

- EFI/\*/shim.efi, EFI/\*/shimx64.efi, EFI/\*/shimx64-fedora.efi Signed binaries for secure boot.

*/etc/*

- /etc/.updated Systemd may create this file on update; it contains a timestamp.

- /etc/lsb-release, /etc/machine-info, /etc/release, /etc/version Information about the installed Linux distro.

- /etc/\*.release, /etc/\*-release, /etc/\*\_version Information about the installed Linux distro.

- /etc/abrt/ Automated bug-reporting tool configuration.

- /etc/acpi/ ACPI events and handler scripts.

- /etc/adduser.conf Configuration file for the adduser and addgroup commands.

- /etc/adjtime Information about hardware clock and drift.

- /etc/aliases, /etc/aliases.d/ Email address alias files.

- /etc/alternatives Configuration of alternative commands.

- /etc/anaconda/ Fedora installer configuration.

- /etc/apache2/ Apache web server configuration.

- /etc/apparmor/, /etc/apparmor.d/ AppArmor configuration and profiles.

- /etc/apport/ Ubuntu crash reporter configuration.

- /etc/appstream.conf AppStream universal package manager configuration.

- /etc/apt/ Debian APT configuration.

- /etc/audit/audit.rules, /etc/audit/rules.d/\*.rules Linux audit system rules.

- /etc/authselect/ Fedora authselect configuration

- /etc/autofs/, /etc/autofs.\* Configure auto-mounting filesystems on demand.

- /etc/avahi/ Avahi (zero-conf) daemon configuration.

- /etc/bash.bash_logout Bash shell system-wide logout script.

- /etc/bashrc, /etc/bash.bashrc Bash shell system-wide login script.

- /etc/binfmt.d/\*.conf Configure additional binary formats for executables at boot.

- /etc/bluetooth/\*.conf Bluetooth configuration files.

- /etc/ca-certificates/, /etc/ca-certificates.conf System-wide certificate authorities (trusted and blocked).

- /etc/casper.conf Config file for initramfs-tools to boot live systems.

- /etc/chrony\* Configuration for the Chrony alternative time sync daemon.

- /etc/conf.d/ Arch Linux configuration files.

- /etc/cron* Cron scheduling configuration.

- /etc/crontab, /etc/anacrontab, /etc/cron.\* Scheduled cron jobs.

- /etc/crypttab Specifies how to mount cryptographic filesystems.

- /etc/ctdb/ Manjaro’s crash handler configuration.

- /etc/cups/ CUPS printer configuration files.

- /etc/dbus-1/ D-Bus configuration (system and session).

- /etc/dconf/ dconf configuration database.

- /etc/debconf.conf The Debian configuration system.

- /etc/default/ Default configuration files for various daemons and subsystems.

- /etc/defaultdomain Default NIS domain name.

- /etc/deluser.conf Config file for the deluser and delgroup commands.

- /etc/dhclient*.conf, /etc/dhcp\* DHCP configuration.

- /etc/dnf/ Fedora DNF package management configuration.

- /etc/dnsmasq.conf, /etc/dnsmasq.d/ Settings for DNSMasq, DNS, and DHCP servers.

- /etc/dpkg/ Debian configuration settings.

- /etc/dracut.conf, /etc/dracut.conf.d/ Dracut config for creating the initramfs image.

- /etc/environment, /etc/environment.d/ Set environment variables for the systemd user instance.

- /etc/ethertypes Ethernet frame types.

- /etc/exports NFS filesystem exports.

- /etc/fake-hwclock.data Contains a recent timestamp for systems without a clock (such as Raspberry Pi).

- /etc/firewalld/ Configuration files for the firewalld daemon.

- /etc/flatpak/ Flatpak configuration and repos.

- /etc/fscrypt.conf Cryptographic filesystems mounted at boot.

- /etc/fstab Filesystems mounted at boot.

- /etc/ftpusers List of forbidden FTP users.

- /etc/fuse3.conf, /etc/fuse.conf Configure the userspace filesystem.

- /etc/fwupd/\*.conf Configure the firmware update daemon.

- /etc/gconf/ GNOME 2 configuration database.

- /etc/gdm/, /etc/gdm3/ Configuration for the GNOME display manager (GDM).

- /etc/geoclue/geoclue.conf Configuration of the GeoClue geolocation service.

- /etc/gnupg/gpgconf.conf Default configuration of GnuPG/GPG.

- /etc/group, /etc/group- Files with group information.

- /etc/gshadow Group shadow file (contains hashed passwords).

- /etc/hostapd/ Configuration for Linux as a Wi-Fi access point.

- /etc/hostid A unique identifier for a system.

- /etc/hostname Hostname defined for a system (this is not globally unique).

- /etc/hosts A list of hosts and matching IPs.

- /etc/hosts.allow, /etc/hosts.deny TCP wrappers access control files.

- /etc/init.d/ Traditional System V init scripts.

- /etc/init/\*, /etc/rc\*.d/ Legacy init system.

- /etc/initcpio/, /etc/mkinitcpio.conf, /etc/mkinitcpio.d/, /etc/initramfstools/\* Configuration and files for initramfs creation.

- /etc/inittab Traditional System V init and runlevel configuration.

- /etc/issue, /etc/issue.d/, /etc/issue.net Banners displayed during network login.

- /etc/iwd/ iNet Wireless Daemon configuration.

- /etc/linuxmint/info, /etc/mintSystem.conf Linux Mint-specific information.

- /etc/locale.conf Contains variables defining the locale settings.

- /etc/locale.gen Contains the list of locales to be included.

- /etc/localtime Symbolic link to a time zone file in /usr/share/zoneinfo/\*.

- /etc/login.defs System-wide configuration for the login program.

- /etc/logrotate.conf, /etc/logrotate.d/ Log rotation configuration.

- /etc/lvm/* Linux Volume Manager configuration and profiles.

- /etc/machine-id Unique identifier for the system.

- /etc/magic, /etc/magic.mime, /etc/mime.types, /etc/mailcap Files that identify and associate content with programs.

- /etc/mail.rc Commands run by the BSD mail or mailx programs.

- /etc/mdadm.conf, /etc/mdadm.conf.d/ Linux software RAID configuration.

- /etc/modprobe.d/, /modules, /etc/modules-load.d/ Kernel modules loaded at boot.

- /etc/motd Traditional Unix message of the day, displayed at login.

- /etc/netconfig Network protocol definitions.

- /etc/netctl/ netctl network manager configuration files.

- /etc/netgroup NIS network groups file.

- /etc/netplan/ Ubuntu netplan network configuration files.

- /etc/network/ Debian network configuration directory.

- /etc/NetworkManager/system-connections/ Network connections, including Wi-Fi and VPNs.

- /etc/networks Associates names to IP networks.

- /etc/nftables.conf Common file for specifying nftables rules.

- /etc/nscd.conf Name service cache daemon configuration file.

- /etc/nsswitch.conf Name service switch configuration file.

- /etc/ntp.conf Network time protocol (NTP) configuration file.

- /etc/openvpn/ OpenVPN client and server configuration.

- /etc/ostree/\*, /etc/ostree-mkinitcpio.conf OSTree versioned filesystem tree configuration.

- /etc/PackageKit/\* PackageKit configuration files.

- /etc/pacman.conf, /etc/pacman.d/ Arch Linux Pacman package manager configuration.

- /etc/pam.conf, /etc/pam.d/ Pluggable Authentication Modules (PAM).

- /etc/pamac.conf Arch Linux graphical package manager configuration.

- /etc/papersize, /etc/paperspecs Default paper size and specifications.

- /etc/passwd, /etc/passwd-, /etc/passwd.YaST2save Files with user account information.

- /etc/polkit-1/ Policy Kit rules and configuration.

- /etc/products.d/ SUSE Zypper product information.

- /etc/profile, /etc/profile.d/ Startup file for login shells.

- /etc/protocols List of protocol numbers.

- /etc/resolv.conf, /etc/resolvconf.conf DNS resolver configuration files.

- /etc/rpm/ Red Hat Package Manager (RPM) configuration.

- /etc/rsyslog.conf, /etc/rsyslog.d/\*.conf rsyslog daemon configuration.

- /etc/sane.d/\*.conf SANE scanner configuration files.

- /etc/securetty Terminals where root is allowed to log in.

- /etc/security/ Directory where packages can store security configuration.

- /etc/services List of TCP and UDP port numbers with associated names.

- /etc/shadow, /etc/shadow-, /etc/shadow.YaST2save Shadowed password files (contains encrypted passwords).

- /etc/shells List of valid login shells.

- /etc/skel/ Default files for a new user (including “." files).

- /etc/ssh/ Secure Shell (SSH) server and default client configuration.

- /etc/ssl/ SSL/TLS configuration and keys.

- /etc/sssd/ System Security Services daemon (sssd) configuration.

- /etc/sudoers, /etc/sudoers.d/, /etc/sudo.conf sudo configuration files.

- /etc/swid/ Software identification tags.

- /etc/sysconfig/ System configuration files; typically for Red Hat or SUSE.

- /etc/sysctl.conf, /etc/sysctl.d/ Values to be read in by sysctl at boot or by command.

- /etc/syslog-ng.conf, /etc/syslog.conf syslog-ng and traditional syslog configuration files.

- /etc/systemd/\*.conf Configuration files for systemd daemons.

- /etc/systemd/network/ Systemd link, netdev, and network (ini-style) configuration files.

- /etc/systemd/system/, /usr/lib/systemd/system/ Systemd unit files for system instance.

- /etc/systemd/user/, /usr/lib/systemd/user/, ~/.config/systemd/user/ Systemd unit files for user instance.

- /etc/tcsd.conf TrouSerS Trusted Computing daemon configuration file (TPM module)

- /etc/tlp.conf, /etc/tlp.d/ Configuration for the laptop power tool.

- /etc/trusted-key.key DNSSEC trust anchor keys.

- /etc/ts.conf Configuration for touchscreen library.

- /etc/udev/ systemd-udev rules and configuration.

- /etc/udisks2/modules.conf.d/, /etc/udisks2.conf udisks disk manager configuration.

- /etc/ufw/ Uncomplicated Firewall rules and configuration.

- /etc/update-manager/ Configuration for the update-manager graphical tool.

- /etc/updatedb.conf Configuration for the mlocate database.

- /etc/vconsole.conf Configuration file for the virtual console.

- /etc/wgetrc Configuration for the wget tool to download files.

- /etc/wicked/ Configuration files for the SUSE Wicked network manager.

- /etc/wireguard/ Configuration files for WireGuard VPN.

- /etc/wpa_supplicant.conf WPA supplicant daemon configuration file.

- /etc/X11/ Configuration for Xorg (xinitrc, xserverrc, Xsession, and so on).

- /etc/xattr.conf Owned by attr, for XFS extended attributes.

- /etc/xdg/ XDG system-wide desktop configuration files (including autostart and user-dirs.defaults).

- /etc/YaST2/* SUSE YaST system-wide configuration.

- /etc/yum.repos.d/ Fedora YUM repository configuration data.

- /etc/zsh/, /etc/zshrc, /etc/zprofile, /etc/zlogin, /etc/zlogout Login and logout files for Z shell.

- /etc/zypp/ SUSE Zypper package management configuration.

*.cache/*

- .cache/clipboard-indicator@tudmotu.com/registry.txt GNOME clipboard history.

- .cache/flatpak/ User-cached Flatpak data.

- .cache/gnome-software/shell-extensions/ User-installed GNOME extensions.

- .cache/libvirt/qemu/log/linux.log QEMU virtual machine activity.

- .cache/sessions/ Desktop session state data.

- .cache/simple-scan/simple-scan.log Scan application log (may contain filenames of saved scans).

- .cache/thumbnails/, .cache/thumbs-\*/ Cached thumbnail images.

- .cache/tracker/, .cache/tracker3/ GNOME search index files.

- .cache/xfce4/clipman/textsrc Xfce clipboard history.

- .cache/\*/ Any other application that may cache persistent data for performance or efficiency reasons.

*.config/*

- .config/autostart/ Autostarting \*.desktop programs and plug-ins.

- .config/baloofilerc Baloo desktop search configuration.

- .config/dconf/user dconf user configuration database.

- .config/goa-1.0/accounts.conf GNOME online accounts configuration.

- .config/g\*rc GNOME override configuration files beginning with g and ending with rc.

- .config/Jitsi Meet/ Cache, state, preferences, logs, and so on from Jitsi video calls.

- .config/kdeglobals KDE global override settings.

- .config/k\*rc, .config/plasma\*rc KDE/Plasma override configuration files beginning with k and ending with rc.

- .config/libaccounts-glib/accounts.db KDE configured cloud account data.

- .config/mimeapps.list User default applications for file types.

- .config/Qlipper/qlipper.ini Clipboard data (Lubuntu).

- .config/session/, gnome-session/ Saved state of desktop and applications.

- .config/systemd/user/ User systemd unit files.

- .config/user-dirs.dirs User-defined default freedesktop directories.

- .config/xsettingsd/xsettingsd.conf X11 settings configuration.

- .config/\*/ Any other application that may save user configuration data.

*.local/*

- .local/lib/python/site-packages User-installed Python modules.

- .local/share/akonadi/ KDE/Plasma Akonadi personal information manager search database.

- .local/share/baloo/ KDE/Plasma Baloo file search database.

- .local/share/dbus-1/ User-configured D-Bus session services.

- .local/share/flatpak/ User-installed Flatpak software packages.

- .local/share/gvfs-metadata/ GNOME virtual filesystem artifacts.

- .local/share/kactivitymanagerd/ KDE KActivities manager.

- .local/share/keyrings/ GNOME keyring files.

- .local/share/klipper/history2.lst KDE clipboard history.

- .local/share/kwalletd/ KDE Wallet files.

- .local/share/modem-manager-gui/ Application for mobile networks (SMS).

- .local/share/RecentDocuments/ \*.desktop files with recent documents information.

- .local/share/recently-used.xbel Recently used files for GTK applications.

- .local/share/Trash/ Trash directory from the freedesktop.org specification.

- .local/share/xorg/Xorg.0.log Xorg startup log.

- .local/user-places.xbel Recently visited locations for GTK applications.

- .local/cache/\*/ Any other application that may save data.

*Other Dot Files and Directories*

- .bash_history Bash shell history file.

- .bash_logout Bash shell logout script.

- .bash_profile, .profile, .bashrc Bash shell login scripts.

- .ecryptfs/ Common default directory for encrypted Ecryptfs tree.

- .gnome2/keyrings/ Legacy GNOME 2 keyrings.

- .gnupg/ GnuPG/GPG directory with configuration and keys.

- .john/ John the Ripper password cracker.

- .mozilla/ Firefox browser directory; includes profiles, configuration, and so on.

- .ssh/ SSH directory with configuration, keys, and known hosts.

- .thumbnails/ Legacy thumbnail image directory.

- .thunderbird/ Thunderbird email client directory; includes profiles, configuration, cached emails, and so on.

- .Xauthority X11 MIT Magic Cookie file.

- .xinitrc User-customized X11 session startup script.

- .xsession-errors, .xsession-errors.old X11 current and previous session error log.

*/usr/*

/usr/bin/, /usr/sbin/ Contains executable files; symlinked if bin and sbin have been merged.

/usr/games/ Directory for game programs.

/usr/include/ System C header (\*.h) files.

/usr/lib/, /usr/lib64/, /usr/lib32/, /usr/libx32/ Contains libraries and executables; architecture-dependent libraries in separate directories.

/usr/local/, /usr/local/opt/ Directories for optional add-on software packages.

/usr/opt/ Alternative location for add-on packages.

/usr/src/ System source code.

*/usr/lib/*

- /usr/lib/ Static and dynamic libraries and supporting files for systemwide use.

- /usr/libexec/ Executables for daemons and system components (not administrators).

- /usr/lib/locale/locale-archive Binary file built with configured locales.

- /usr/lib/modules/, /usr/lib/modprobe.d/, /usr/lib/modules-load.d/ Kernel modules and configuration files.

- /usr/lib/os-release File containing information about installed distro.

- /usr/lib/python*/ System-wide Python modules and support files.

- /usr/lib/sysctl.d/ Default sysctl configuration files.

- /usr/lib/udev/ udev support files and rules (rules.d/).

- /usr/lib/tmpfiles.d/ Configuration for temporary files and directories.

- /usr/lib/systemd/

- /lib/systemd/system/ Default system unit files.

- /lib/systemd/user/ Default user unit files.

- /usr/lib/systemd/\*generators\*/ Generator programs to create unit files.

- /usr/lib/systemd/network/ Default network, link, and netdev files.

- /usr/lib/systemd/systemd* Systemd executables.

*/usr/local/*

- /usr/local/ Directory was the traditional Unix location for locally installed binaries, and not from a network-mounted directory. Linux systems may use it for add-on packages.

- /usr/local/bin/, /usr/local/sbin/ Local binaries.

- /usr/local/etc/ Local configuration.

- /usr/local/doc/, /usr/local/man/ Local documentation and man pages.

- /usr/local/games/ Local games.

- /usr/local/lib/, /usr/local/lib64/, /usr/local/libexec/ Associated local files.

- /usr/local/include/, /usr/local/src/ Header files and source code.

- /usr/local/share/ Architecture-independent files.
*/usr/share/*

- /usr/share/ Files shared between software packages or different architectures.

- /usr/share/dbus-1/ Default system and session D-Bus configuration data.

- /usr/share/factory/etc/ Initially installed defaults of some /etc/ files.

- /usr/share/hwdata/pci.ids List of PCI vendors, devices, and subsystems.

- /usr/share/hwdata/usb.ids List of USB vendors, devices, and interfaces.

- /usr/share/hwdata/pnp.ids List of product vendor name abbreviations.

- /usr/share/i18n/, /usr/share/locale/ Internationalization data.

- /usr/share/metainfo/ XML files with AppStream metadata.

- /usr/share/polkit-1/ PolicyKit rules and actions.

- /usr/share/zoneinfo/ Time zone data files for different regions.

- /usr/share/accounts/ Service and provider files for KDE online accounts.

- /usr/share/doc/ Software package supplied documentation.

- /usr/share/help/ GNOME help files with translations.

- /usr/share/man/ Man pages with translations.

- /usr/share/src/, /usr/share/include/ Source code; C header (\*.h) files.

*/var/*

- /var/backups/ Debian backup data of packages, alternatives, and passwd/group files.

- /var/games/ Variable data from installed games; may contain high-score files with names and dates.

- /var/local/ Variable data for software installed in /usr/local/.

- /var/opt/ Variable data for software installed in /usr/opt/.

- /var/run/ Runtime data; usually empty on a forensic image.

- /var/tmp/ Temporary files; persistent across boots.

- /var/crash/ Crash dumps, stack traces, and reports.

- /var/mail/ Locally spooled email (some distros like Ubuntu and Fedora don’t set up a mail - subsystem by default anymore).

- /var/www/ A default location for storing HTML pages.

- /var/db/sudo/lectured/ Empty files indicating a user has been “lectured” about using sudo for the first time.

- /var/cache/

- /var/cache/ Persistent cached system-wide data.

- /var/cache/apt/ Cached downloads of Debian packages.

- /var/cache/cups/ CUPS printing system.

- /var/cache/cups/job.cache Print job cache with filenames, timestamps, and printer names.

- /var/cache/cups/job.cache.* Rotated versions of job.cache.

- /var/cache/debconf/ System-wide cached Debian data.

- /var/cache/debconf/passwords.dat Contains system-generated passwords.

- /var/cache/dnf/ System-wide cached Fedora DNF package data.

- /var/cache/PackageKit/ Distro-independent system-wide cached PackageKit package data.

- /var/cache/pacman/ System-wide cached Arch Linux Pacman package data.

- /var/cache/snapd/ System-wide Ubuntu Snap package cached data.

- /var/cache/zypp/ System-wide cached SUSE Zypper package data.

- /var/log/

- /var/log/alternatives.log Debian alternative command name system.

- /var/log/anaconda/ Fedora Anaconda initial installer logs.

- /var/log/apache2/ Default Apache web server logs.

- /var/log/apport.log Ubuntu crash handling system log.

- /var/log/apt/ Debian Apt package manager logs.

- /var/log/aptitude Debian Aptitude actions logged.

- /var/log/archinstall/install.log Arch Linux initial install log.

- /var/log/audit/ Linux Audit system logs.

- /var/log/boot.log Plymouth splash console output.

- /var/log/btmp Log of failed (bad) login attempts.

- /var/log/Calamares.log Calamares initial installation log.

- /var/log/cups/ CUPS printing system access, error, and page logs.

- /var/log/daemon.log Common syslog file for daemon-related logs.

- /var/log/ Default location for system-wide logfiles.

- /var/log/dmesg Log of kernel ring buffer.

- /var/log/dnf.log Fedora DNF package manager logs.

- /var/log/dpkg.log Debian dpkg package manager logs.

- /var/log/firewalld firewalld daemon logs.

- /var/log/hawkey.log Fedora Anaconda log.

- /var/log/installer/ Debian initial installer logs.

- /var/log/journal/ Systemd journal logs (system and user).

- /var/log/kern.log Common syslog file for kernel-related logs (ring buffer).

- /var/log/lastlog Log of last logins with origin information.

- /var/log/lightdm/ Lightdm display manager logs.

- /var/log/mail.err Common syslog file for mail-related errors.

- /var/log/messages Traditional Unix logfile with syslog messages.

- /var/log/mintsystem.log, mintsystem.timestamps Linux Mint-specific logs.

- /var/log/openvpn/ OpenVPN system logs.

- /var/log/pacman.log Arch Linux Pacman package manager logs.

- /var/log/sddm.log SDDM display manager log.

- /var/log/tallylog PAM tally state file for failed login attempts.

- /var/log/ufw.log Uncomplicated Firewall logs.

- /var/log/updateTestcase-\*/ SUSE bug report data.

- /var/log/wtmp Traditional system login records.

- /var/log/Xorg.0.log Xorg startup log.

- /var/log/YaST2 SUSE YaST logs.

- /var/log/zypper.log SUSE Zypper package manager logs.

- /var/log/zypp/history SUSE Zypper package manager history.

- /var/log/* Other logs created by applications or system components.

- /var/lib/

- /var/lib/ Persistent variable data for installed software.

- /var/lib/abrt/ Automated bug reporting tool data.

- /var/lib/AccountsService/icons/* User’s chosen login icons.

- /var/lib/AccountsService/users/* User’s default or last session login settings.

- /var/lib/alternatives/ Symlinks to alternative command names.

- /var/lib/bluetooth/ Bluetooth adapters and paired Bluetooth devices.

- /var/lib/ca-certificates/ System-wide CA certificate repository.

- /var/lib/dnf/ Fedora DNF install package information.

- /var/lib/dpkg/, /var/lib/apt/ Debian-installed package information.

- /var/lib/flatpak/ Flatpak installed package information.

- /var/lib/fprint/ Fingerprint reader data, including enrolled user fingerprints.

- /var/lib/gdm3/ GNOME 3 display manager settings and data.

- /var/lib/iwd/ iNet Wireless Daemon, including access point information, passwords.

- /var/lib/lightdm/ Lightdm display manager settings and data.

- /var/lib/linuxmint/mintsystem/ Linux Mint system-wide settings.

- /var/lib/mlocate/mlocate.db File database for the locate search command.

- /var/lib/NetworkManager/ Network Manager data, including leases, bssids, and more.

- /var/lib/PackageKit/ PackageKit transactions.db.

- /var/lib/pacman/ Arch Linux Pacman data.

- /var/lib/polkit-1/ PolicyKit data.

- /var/lib/rpm/ RPM SQLite package database.

- /var/lib/sddm/ SDDM display manager data.

- /var/lib/selinux/ SELinux modules, locks, and data.

- /var/lib/snapd/ Ubuntu installed Snap package information.

- /var/lib/systemd/ System-wide systemd data.

- /var/lib/systemd/coredump/ Systemd core dump data.

- /var/lib/systemd/pstore/ Crash dump data saved by pstore.

- /var/lib/systemd/timers/ Systemd timer unit files.

- /var/lib/systemd/timesync/clock Empty file; mtime can be used to set approximate time on systems without a hardware clock.

- /var/lib/ucf Update configuration file data.

- /var/lib/upower/ Power history files (charging/discharging on laptops).

- /var/lib/whoopsie/whoopsie-id Unique identifier for crash data sent to Ubuntu/Canonical servers.

- /var/lib/wicked/ Wicked network manager data.

- /var/lib/YaST2/ SUSE YaST configuration data.

- /var/lib/zypp/AnonymousUniqueId Unique identifier for contacting SUSE servers.

- /var/lib/zypp/ SUSE Zypper package manager data.

- /var/spool/

- /var/spool/ Location for daemons using a spool directory for jobs.

- /var/spool/abrt/, /var/tmp/abrt Crash reporting data sent to Fedora.

- /var/spool/at/ Scheduled at jobs to run.

- /var/spool/cron/, /var/spool/anacron/ Scheduled cron jobs to run.

- /var/spool/cups/ CUPS printing spool directory.

- /var/spool/lpd/ Traditional line printer daemon spool directory.

- /var/spool/mail/ See /var/mail/.

</details>


# Resources

[https://nostarch.com/practical-linux-forensics](https://nostarch.com/practical-linux-forensics) is my primery resource.

[https://www.kernel.org/doc/html/latest/](https://www.kernel.org/doc/html/latest/)