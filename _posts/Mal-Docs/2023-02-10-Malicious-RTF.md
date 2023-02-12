---
title: "Malicious RTF File"
classes: wide
header:
  teaser: /assets/images/mal-docs/Malicious-RTF/exploit.png
ribbon: DodgerBlue
description: "Investigation for Phishing RTF File ..."
categories:
  - Mal-Docs
toc: true
---

# Sample info 

We are given a RTF File with the hash 

    sha256  9681ef910820d553e4cd54286f8893850a3a57a29df7114c6a6b0d89362ff326

Which is confirem using the "file" utility to be an `RTF`

![error loading](/assets/images/mal-docs/Malicious-RTF/file.png)

# Analyzing

At the start i looked for any OleObject embedded using the command

    rtfdump.py -f O unknown.rtf

    note : 
      unkwon is the name of the file

![error loading](/assets/images/mal-docs/Malicious-RTF/ole.png)

To take a look at each stream use the ‘-s’ argument and the corresponding number rtfdump has assigned it.

    rtfdump.py -s 540 -H unknown.rtf

And as expected we see the magic bytes of an OleObject and a bunch of data.

![error loading](/assets/images/mal-docs/Malicious-RTF/magic.png)

And in one of the OleObjects we can see "Equation2" which will indecate that this rtf file is trying to exploit a vulnrability in that application to drop the file that you can see in the first OleObject "ghb4nrwmp.wmf"

![error loading](/assets/images/mal-docs/Malicious-RTF/exploit.png)
