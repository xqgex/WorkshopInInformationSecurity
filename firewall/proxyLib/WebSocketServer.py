#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
from select import select

class WebSocketServer(object):
	def __init__(self, config):
		self.config = config
		self.proxy_ip = self.config.get("connection", "proxy_ip")
		self.proxy_port = int(self.config.get("connection", "proxy_port"))
		self.running = True # Keep serving requests
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.proxy_ip, self.proxy_port))

	def listen(self, backlog=5): # Listen for requests
		print("Listening on {}".format(self.proxy_port))
		while self.running:
			print "\nwaiting to receive message"
			try:
				data, address = self.socket.recvfrom(4096)
			except socket.error, e:
				print "Connection error"
			print "received {} bytes from {}".format(len(data), address)
			print data
			if data:
				if data == "Close_Connection":
					self.running = False
				else:
					sent = self.socket.sendto(data, address)
					print "sent {} bytes back to {}".format(sent, address)
		print "Thread {} stopped".format(self.ident)
