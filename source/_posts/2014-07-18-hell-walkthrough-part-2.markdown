---
author: recrudesce
comments: false
date: 2014-07-18 20:27:04+00:00
layout: post
slug: hell-walkthrough-part-2
title: Hell Walkthrough – Part 2
wordpress_id: 101
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

[Part 1](http://fourfourfourfour.co/2014/07/17/hell-walkthrough-part-1/) | Part 2 | [Part 3](http://fourfourfourfour.co/2014/07/19/hell-walkthrough-part-3/) | [Part 4](http://fourfourfourfour.co/2014/07/20/hell-walkthrough-part-4/) | [Part 5](http://fourfourfourfour.co/2014/07/21/hell-walkthrough-part-5/)

So, yesterday we got a shell on Hell as www-data. Today we'll escalate through some of the users on our quest to root.  If you've not read [Part 1](http://fourfourfourfour.co/2014/07/17/hell-walkthrough-part-1/), I suggest you do so now.  I'll wait.  Go on, don't be shy, I'll still be here when you get back.

Done ?  Great - let us continue.
<!-- more -->
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


Thank you, Jack, for being a predictable - yet persistent - weirdo. A quick hop and a skip over to the worryingly named milk_4_life account and we can carry.


``` bash

$ su milk_4_life
Password: 4J0WWvL5nS

$ whoami
milk_4_life
$ 
```


Tomorrow we'll play a game. Oooh, cryptic.
