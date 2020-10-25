
# Precision Matching
For this challenge we are given:
- An in-browser YARA implementation that runs our rules against a list of binary files, only some of which we want to flag as malware.
- One of the binaries that we need to mark as malware.
- Information saying that the author of the malware used the following:
a) dynamic imports for their calls to CreateRemoteThread
b) Visual Studio 2019

## What is this YARA stuff?
After a quick google search, I ended up at the  [documentation](http://https://yara.readthedocs.io/en/stable/writingrules.html "documentation"). Apparently it is a tool that is used to write rules against which files are checked to see if they are potentially malicious. Here is a basic example that returns true if a file is a PNG (or at least contains the header somewhere in it) :
```
rule rule_name
{
	//Define string variables
	strings:
									//PNG Magic Number
		$my_hex_string = {89 50 4E 47 D A 1A A}

	//Define return values
    condition:
        $my_hex_string
}
```
## The PE module
There are also many modules that can be accessed through imports that make life easier. Since the binaries we are trying to flag are .exe files, Taking a look at the documentation for the [portable executable](http://https://yara.readthedocs.io/en/stable/modules/pe.html "portable executable") module could be useful.

Considering we are trying to detect imports, it looks like the [imports](http://https://yara.readthedocs.io/en/stable/modules/pe.html#c.imports "imports") function will help us:
`imports(dll_name, function_name)
`

After looking for a way to tell what version of Visual Studio was used to create the binary, it [looks](http://https://stackoverflow.com/questions/40831299/can-i-tell-what-version-of-visual-studio-was-used-to-build-a-dll-by-examining-th "looks") like looking at the linker version is the way to go. Conveniently, there is also an easy way to look at that as well with [linker_version](http://https://yara.readthedocs.io/en/stable/modules/pe.html#c.linker_version "linker_version").major and .minor:
`linker_version.major` and `linker_version.minor`
## Investigation
Now that we know what functions we want to use, we need to find the linker version we will compare against and the name of the dll and function we will check with imports().
### The Linker Version
After searching for a tool that could give metadata on .exe files, I [learned](http://https://superuser.com/questions/1060460/how-to-get-from-a-exe-executable-file-the-version-author-publisher-etc-and "learned") that exiftool could do the job. Running it against the binary: 
```bash
kali@kali:~/MetaCTF2020/yara$ exiftool malware-dyn-vs19-variant0.exe
ExifTool Version Number         : 12.06
File Name                       : malware-dyn-vs19-variant0.exe
Directory                       : .
File Size                       : 286 kB
File Modification Date/Time     : 2020:10:23 20:41:18-04:00
File Access Date/Time           : 2020:10:24 19:59:53-04:00
File Inode Change Date/Time     : 2020:10:24 19:59:05-04:00
File Permissions                : rw-r--r--
File Type                       : Win64 EXE
File Type Extension             : exe
MIME Type                       : application/octet-stream
Machine Type                    : AMD AMD64
Time Stamp                      : 2020:10:23 13:19:52-04:00
Image File Characteristics      : Executable, Large address aware
PE Type                         : PE32+
Linker Version                  : 14.26
Code Size                       : 180224
Initialized Data Size           : 117248
Uninitialized Data Size         : 0
Entry Point                     : 0xd490
OS Version                      : 6.0
Image Version                   : 0.0
Subsystem Version               : 6.0
Subsystem                       : Windows command line

```
It looks like the linker version is 14.26.
### Import Parameters
Doubting that there would be a program that could do this for me, I decided to open up the binary file in a hex editor and see would I could find that related to CreateRemoteThread. It turned out to be fairly straightforward. Searching for the string "CreateRemoteThread" left me looking at this:
```
0002c8b0: 6f6f 206c 6f6e 6700 4300 3a00 5c00 5700  oo long.C.:.\.W.
0002c8c0: 6900 6e00 6400 6f00 7700 7300 5c00 6500  i.n.d.o.w.s.\.e.
0002c8d0: 7800 7000 6c00 6f00 7200 6500 7200 2e00  x.p.l.o.r.e.r...
0002c8e0: 6500 7800 6500 0000 5300 5900 5300 5400  e.x.e...S.Y.S.T.
0002c8f0: 4500 4d00 5c00 4500 7800 6500 6300 7500  E.M.\.E.x.e.c.u.
0002c900: 7400 6900 6f00 6e00 5f00 6700 7500 6100  t.i.o.n._.g.u.a.
0002c910: 7200 6400 7200 6100 6900 6c00 0000 0000  r.d.r.a.i.l.....
0002c920: 4300 3a00 5c00 5000 7200 6f00 6700 7200  C.:.\.P.r.o.g.r.
0002c930: 6100 6d00 4400 6100 7400 6100 5c00 4d00  a.m.D.a.t.a.\.M.
0002c940: 6100 6c00 7700 6100 7200 6500 0000 0000  a.l.w.a.r.e.....
0002c950: 4372 6561 7465 5265 6d6f 7465 5468 7265  CreateRemoteThre
0002c960: 6164 0000 0000 0000 6b00 6500 7200 6e00  ad......k.e.r.n.
0002c970: 6500 6c00 3300 3200 2e00 6400 6c00 6c00  e.l.3.2...d.l.l.
0002c980: 0000 0000 0000 0000 6d00 6100 6c00 7700  ........m.a.l.w.
0002c990: 6100 7200 6500 2e00 6400 6c00 6c00 0000  a.r.e...d.l.l...

```
While it is a bit odd that most off the characters are separated by null bytes, you can clearly see `kernel32.dll` and `malware.dll` hanging arund `CreateRemoteThread`. We can try both.
## Putting it all together
So far we know we want a rule that imports pe and somehow uses the linker version and imports function to check files. That leaves us with a file looking something like this:
```
import "pe"

rule yarp {
    condition:
        pe.linker_version == ?? and pe.imports(??, ??)
}

```
We will test them one at a time so it is easier to debug, starting with the linker version. Considering that it's not likely the minor version numbers will match for different versions of Visual Studio, lets test against that first.
```
import "pe"

rule yarp {
    condition:
        pe.linker_version.minor == 26
}

```
![Image](https://github.com/ZacharyTraul/Pwn-Rev/blob/main/opera_2020-10-24_22-17-08.png?raw=true)

Awesome! It looks like that eliminated all the files made in Visual Studio 17. We still have the statically linked files, but checking the imports should take care of that. Considerign that CreateRemoteThread comes from kernel32.dll, we will test against that first.
```
import "pe"

rule yarp {
    condition:
        pe.imports("kernel32.dll", "CreateRemoteThread")
}

```
![Image](https://github.com/ZacharyTraul/Pwn-Rev/blob/main/opera_2020-10-24_22-21-39.png?raw=true)

Hmm. That seems to have done the opposite of what we wanted, let us try prepending it with a not instead.

```
import "pe"

rule yarp {
    condition:
        not pe.imports("kernel32.dll", "CreateRemoteThread")
}

```
![Image](https://github.com/ZacharyTraul/Pwn-Rev/blob/main/opera_2020-10-24_22-22-43.png?raw=true)

That is much better. It now flags the dynamically linked files.
Finally, we can combine them:
```
import "pe"

rule yarp {
    condition:
        pe.linker_version.minor == 26 and not pe.imports("kernel32.dll", "CreateRemoteThread")
}


```
![Image](https://github.com/ZacharyTraul/Pwn-Rev/blob/main/opera_2020-10-24_22-31-09.png?raw=true)
Looks like it worked!
## Closing Thoughts
This is one of my favorite reversing challenges I have done so far. While there was less looking at a disassembler and untangling of functions, this felt much more directly applicable to malware research than most other reversing challenges I have done so far.
