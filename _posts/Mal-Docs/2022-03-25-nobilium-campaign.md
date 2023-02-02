---
title: "Malicious Word File"
classes: wide
header:
  teaser: /assets/images/mal-docs/nobilium/javascript.png
ribbon: DodgerBlue
description: "Investigation for Phishing campaign ..."
categories:
  - Mal-Docs
toc: true
---

# Campain info :
	The attack is believed to be part of the nobilium campaign 
	which is targeting the Israel ambassador and all the people 
	will have the curiosity to know their secrets throw encrypted 
	word document file needs the user to enable content to
	decrypt it. 

# Droper analysis :

the attack starts by sending an email attachment with a word document named "Ambassador_Absense.docx"

### You thought that ".docx" documents are safe?!!

the first look at the file shows us that it has encrypted content and needs you to enable content to 
decrypt it.

![error](/assets/images/mal-docs/nobilium/first.png)

Using "oledump" we can see the embedded files on it 

![error](/assets/images/mal-docs/nobilium/oledump.png)

then we can use "oleobj" to extract the hta stream from the document

![error](/assets/images/mal-docs/nobilium/htastream.png)

Now we have this javascript & VBScript to deal with which contains a huge array and a decryption routine and execution script.

![error](/assets/images/mal-docs/nobilium/javascript.png)

the decryption is so simple it's just xor with hard codded key
then adding the "mz" header to the decrypted DLL file then executing it using "rundll32.exe" 
the file is dropped to 
"C:\Users\user\AppData\Local\Temp\..\IconCacheService.dll"

Now it's time to analyze the Dropped file.

# Droped file analysis :

checking the file type and sha256sum and performing basic static analysis on different techniques like imports, strings, entropy,...etc

![error](/assets/images/mal-docs/nobilium/basic.png)

![error](/assets/images/mal-docs/nobilium/strings.png)

![error](/assets/images/mal-docs/nobilium/entropy.png)

Here we notice that the malware has a TLS section means that there is a tls call-back function that will run before the start point of the application as an anti-debugging or VM technique.

![error](/assets/images/mal-docs/nobilium/tls.png)

Then looking into the exported functions we can quickly understand what this piece of malware does which is to gather the information from the infected machine and send it back to the C2 Server.

![error](/assets/images/mal-docs/nobilium/malfunc.png)

