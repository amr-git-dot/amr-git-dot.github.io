---
title: "malicious pdf"
classes: wide
header:
  teaser: /assets/images/mal-docs/mal-pdf/enc.png
ribbon: DodgerBlue
description: "Investigation for malicious pdf extracted from packet capture ..."
categories:
  - Mal-Docs
toc: true
---
# Discription:

  the network traffic of an incident is captured and your job is to investigate it and know how the machine is compromised and extract The IOCs.


# Pcap analysis:

  at the start, we will follow the HTTP stream that led us to the download of the malicious pdf.

  the malicious link starts with requesting an HTML file that contains just javascript code

![Detection](/assets/images/mal-docs/mal-pdf/initreq.png)
  
  since we already have a packet capture that tells us the results of its execution we don't need to analyze it.

  the js code sends a request asking for a PHP file which redirects the request to another site to download the malicious pdf.

![Detection](/assets/images/mal-docs/mal-pdf/pdfreq.png)

  once we extracted the pdf from the traffic we can start analyzing it.

# PDF analysis:

  using "pdfid" to display info about the pdf 


![Detection](/assets/images/mal-docs/mal-pdf/info.png)

  We notice that the pdf itself contains js code.

  "peepdf" tool can also give us good informations about the pdf using interactive mode "-if"

![Detection](/assets/images/mal-docs/mal-pdf/peepdf.png)

  Now we can extract the js code and then beautify it with any online js beautifiers at this is the final result.

![Detection](/assets/images/mal-docs/mal-pdf/jscode.png)

  now it's time to deobfuscate the script via renaming and reconstruct the logic of it

  here is what we get 

![Detection](/assets/images/mal-docs/mal-pdf/dejs.png)

  we notice that the final payload which gets passed to the "eval" function is gotten from another annotation object from the pdf so we will search for these objects.

  using the tree command we found that annotations are on objects 24,6,8

![Detection](/assets/images/mal-docs/mal-pdf/tree.png)

  following these objects we finally found the pattern that is found in the first stage of the js code.

![Detection](/assets/images/mal-docs/mal-pdf/enc.png)

  now we will use a python script to decode it.

![Detection](/assets/images/mal-docs/mal-pdf/script.png)

 running the script and saving the output to stage2.js then beautifying it we have the following code.

![Detection](/assets/images/mal-docs/mal-pdf/stage2.png)

 we need to apply the same method with the other decoded js in the annotation pdf objects "9 & 7".

 by extracting and decoding each of them the first one will give us the first part of stage3.js 

 here is the last part of it.

![Detection](/assets/images/mal-docs/mal-pdf/firstpart.png)

 The second one will continue to give us the second part of the stage3.js.

 here is the first part of it.

![Detection](/assets/images/mal-docs/mal-pdf/secpart.png)

 By looking at the start of the code execution you will notice that it searches for specific versions of the application and depending on the version of the pdf viewer it will choose the exploit.

![Detection](/assets/images/mal-docs/mal-pdf/version.png)

