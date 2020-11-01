import socket
s = socket.socket()
s.bind(('0.0.0.0', 55555))
s.listen(3)
while True:
    c, addr = s.accept()
    print(addr)
    print(c.recv(1024))
    c.close()
