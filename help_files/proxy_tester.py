#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket, time

PROXY_IP = "127.1.2.0"
PROXY_PORT = 7120
BUFFER_SIZE = 4096

if __name__ == "__main__":
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	for i in range(5):
#		sent = sock.sendto("4d5a40414243444546474849".decode("hex"), (PROXY_IP, PROXY_PORT)) # XXX
#		sent = sock.sendto("aaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 3000\r\nContent-Type: text/plain\r\nContent-aaaa: 0000\r\nContent-bbbb: 1111\r\nContent-Disposition: attachment; filename=\"myfile.ca\"\r\n\r\nsssssssssssssssssssssssss void", (PROXY_IP, PROXY_PORT)) # XXX
#		sent = sock.sendto("GET /objects?../../../../hacked aaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 3000\r\nContent-Type: text/plain\r\nContent-aaaa: 0000\r\nContent-bbbb: 1111\r\nContent-Disposition: attachment; filename=\"myfile.ca\"\r\n\r\nsssssssssssssssssssssssss void", (PROXY_IP, PROXY_PORT)) # XXX
#		sent = sock.sendto("GET /path/to/file.c aaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 3000\r\nContent-Type: text/plain\r\nContent-aaaa: 0000\r\nContent-bbbb: 1111\r\nContent-Disposition: attachment; filename=\"myfile.ca\"\r\n\r\nsssssssssssssssssssssssss void", (PROXY_IP, PROXY_PORT)) # XXX
		break # XXX
#		sent = sock.sendto("Test_Test_Test_Test_Test", (PROXY_IP, PROXY_PORT))
#		print "Waiting for answer (sent {})".format(sent)
#		data, server = sock.recvfrom(BUFFER_SIZE)
#		print "Received {} from {}".format(data, server)
#		time.sleep(3)
#	print "closing socket"
#	sock.sendto("Close_Connection", (PROXY_IP, PROXY_PORT))
	sock.close()

