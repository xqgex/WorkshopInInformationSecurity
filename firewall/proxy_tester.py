#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket, time

PROXY_IP = "127.1.2.0"
PROXY_PORT = 7120
BUFFER_SIZE = 4096

if __name__ == "__main__":
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	for i in range(5):
		sent = sock.sendto("Test Test Test", (PROXY_IP, PROXY_PORT))
		print "Waiting for answer (sent {})".format(sent)
		data, server = sock.recvfrom(BUFFER_SIZE)
		print "Received {} from {}".format(data, server)
		time.sleep(3)
	print "closing socket"
	sock.sendto("Close_Connection", (PROXY_IP, PROXY_PORT))
	sock.close()

