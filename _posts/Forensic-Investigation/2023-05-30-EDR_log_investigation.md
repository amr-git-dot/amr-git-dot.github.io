---
title: "EDR Log Investigation"
classes: wide
header:
  teaser: /assets/images/forensic-investigation/EDR_log_investigation/powershell.png
ribbon: DodgerBlue
description: "Investigating a Case through EDR logs in Kibana"
categories:
  - Forensic investigation
toc: true
---

# Scenario

After a cybersecurity incident, CyberCorp's management decided to purchase and deploy EDR (Endpoint Detection and Response) solution. EDR agents were installed on all workstations and servers and forwarded telemetry to a centralized Threat Hunting platform.

The company has also hired a security blue team of highly qualified analysts to build a threat detection process using the Threat Hunting approach. You will have to try on the role of a threat hunter, who decided to verify the hypothesis about one of the attacker's persistence techniques.

Unfortunately, the hypothesis was confirmed, and a persistence technique was discovered on one host, which eventually became the starting point of the investigation.

By analyzing the EDR telemetry in the Threat Hunting platform, you will have to understand how the attacker compromised the network and what he managed to do with the obtained access.

# Hunting 

When dealing with EDRs keep in mind that each log is saved because of a trigger to a specific role, and each role is assigned a severity level, So we can start our investigation based on that as our first hypothesis.

![Error loading](/assets/images/forensic-investigation/EDR_log_investigation/first.png)

I started to check what interesting filters are there to filter for, and quickly discovered a lot of wrong things going there.

Code Injection from the PowerShell empire module and accessing the lssas application and other messy things.

But for now, I need to get to where all this started and move from there to this point.

By Sorting the time backward and start looking at the alerts I quickly noticed this one.

![Error loading](/assets/images/forensic-investigation/EDR_log_investigation/initial.png)

A Word document initiated a connection out, which seems like an initial footh hold.

And quickly after that an alert of a WMI consumer subscription.

![Error loading](/assets/images/forensic-investigation/EDR_log_investigation/wmi.png)

Seems like a persistence mechanism.

Then executing a PowerShell script for injecting shell code into another process.

![Error loading](/assets/images/forensic-investigation/EDR_log_investigation/inject.png)

Then we can find an injection happens in a system-level process means now the attacker has system privileges and as shown he seems to be started dumping lssas process memory using the comsvcs minidump technique and also started a process named svchost downloaded from the internet using certutil tool.

![Error loading](/assets/images/forensic-investigation/EDR_log_investigation/system.png)

![Error loading](/assets/images/forensic-investigation/EDR_log_investigation/dump.png)

Then the attacker downloaded other scripts into the machine to continue.

![Error loading](/assets/images/forensic-investigation/EDR_log_investigation/download.png)


# TimeLine

- Initial access via Phishing word Document for user "john.goldberg"
- Persistence via wmi event consumer "PowerControl Consumer"
- Execute a PowerShell script that does injection "mso1033.ps1"
- Drops a malicious dll file in temp directory "qb52gom0.dll"
- get winlogon.exe privileges using injection.
- dump lsass memory.
- run a process named svchost.exe downloaded from the internet into the TEMP folder.
- Used a domain admin account.

# IOCs

- 190.150.52.34
- 188.135.15.49:80
- 94.177.253.126
- eb41b254964fb046656a7312c8547674577c4a2229360cc12f5b1289280b92c3
- 54dabbd0a47f5ef839de9183978b9b755c248c8ad7a35aff3fe537990ffb3501
- 65df8039cbd1b3fb40a1cc9198c2ba314dd38ff7d301ee475327d438346d96af
