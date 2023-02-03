---
title: "Malicious ISO File"
classes: wide
header:
  teaser: /assets/images/mal-docs/Malicious_ISO/child.png
ribbon: DodgerBlue
description: "Investigation for Phishing ISO File ..."
categories:
  - Mal-Docs
toc: true
---

# Sample info

We are given a sample with hash

    sha256  a063b8a55c4ee1bee4f58ff27b312459b80c8895be0addaa069809a9eb7a1036

For parsing iso files there is a python library called "isoparser" which you can download using command...

    pip install isoparser

you can create an iso object from an .iso file, and then I list the children of the root object

     import isoparser
     iso = isoparser.parse('unknown.iso')
     iso.root.children

![error loading](/assets/images/mal-docs/Malicious_ISO/child.png)

The root folder contains one file'FEDEX AWB.EXE'.

Looking into the content of file "FEDEX AWB.EXE" I see the header is MZ.

![error loading](/assets/images/mal-docs/Malicious_ISO/content.png)

here is a small python script that can extract the children executable to stdout...

```py
import isoparser
import sys
import os
 
oIsoparser = isoparser.parse(sys.argv[1])
 
if sys.platform == 'win32':
    import msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
sys.stdout.buffer.write(oIsoparser.root.children[0].content)
```
And Now we have our output

![error loading](/assets/images/mal-docs/Malicious_ISO/output.png)