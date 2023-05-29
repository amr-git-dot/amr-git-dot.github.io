---
title: "Splunk AD Threat hunting"
classes: wide
header:
  teaser: /assets/images/forensic-investigation/AD_Threat_Hunting/powershell.png
ribbon: DodgerBlue
description: "Active Directory attack comparison from red teamer/ Threat hunter perspective"
categories:
  - Forensic investigation
toc: true
---

# OverView 

I Got throw a writeup for an Active Directory lab environment where the author started a lateral movement in the environment which was monitored in a Splunk SIEM solution (just Event logs collected), So I will go throw every step on the attack and the resulting logs.

    You can find the attack documentation and the Splunk VM in the resources.

The following image explains the topology of the environment and the path taken to compromise.

![Error loading](/assets/images/forensic-investigation/AD_Threat_Hunting/topology.png)

The attacker started his journey from the `Client01` machine.

# SIEM Setup

As we can see we have just one source which is `Windows Eventlogs`

![Error loading](/assets/images/forensic-investigation/AD_Threat_Hunting/sources.png)


# Hunting

Powershell is one of the most used ways of enumerating the AD environment, So I quickly created a visualization of the PowerShell activity on the Environment.

![Error loading](/assets/images/forensic-investigation/AD_Threat_Hunting/powershell.png)

We will notice that there is a high PowerShell activity from `client02` which is worth investigating.

Looking at the script block field of the event "4104" we can see powerview scripts get executed.

![Error loading](/assets/images/forensic-investigation/AD_Threat_Hunting/powerview.png)

My next step is to check which executables ran in the machine and what command line they executed with.

      index=* host=CLIENT02 NOT "Splunk" NOT "VMware" NOT "edge"
      | stats count by _time, Image, CommandLine, User

You can quickly spot different ways for enumerating the host using hostname, ipconfig, net and others.

![Error loading](/assets/images/forensic-investigation/AD_Threat_Hunting/host.png)

taking a closer look you will be able to spot this.

![Error loading](/assets/images/forensic-investigation/AD_Threat_Hunting/priv.png)

Executing "c:\Program.exe" as the system is an evidence of exploiting unquoted path service vulnerability in one of the services running with system privileges which in our case is "C:\Program Files\Basic Monitoring\Automate-Basic-Monitoring.exe".

Then the attacker was able to create a new user in the machine "HelpDesk" and add him to the local administrators group.

After that, we can notice the use of the "Rubeus" tool to perform a `Pass The Hash` attack against two users "mohamed & it-support" and get a cmd with their privileges.

I found also that there was a request for golden ticket.

![Error loading](/assets/images/forensic-investigation/AD_Threat_Hunting/gold.png)

This means that one of the two compromised users is a domain admin or at least has a DCSync right to get the krbtgt hash.

# Attack Timeline

- Privilege escalation using unquoted service path.
- Add the user to the local admins group.
- The attacker managed to get (mohamed and it-support) users credentials from memory.
- The attacker managed to perform a DCSync attack against the domain controller and extracted krbtgt hash.
- The attacker used extracted krbtgt hash to get a golden ticket.

# Resources

https://alhakami.me/Articles/Compromising_Active_Directory_Environments_with_PowerShell.pdf