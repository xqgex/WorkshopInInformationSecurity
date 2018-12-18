#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
from select import select
from proxyLib.DynamicTable import DynamicTable

MAGIC_SPLIT_CHAR = "_"

class WebSocketServer(object):
	def __init__(self, config):
		self.config = config
		self.proxy_ip = self.config.get("connection", "proxy_ip")
		self.proxy_port = int(self.config.get("connection", "proxy_port"))
		self.running = True # Keep serving requests
		self.dynamic_table = DynamicTable()
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.proxy_ip, self.proxy_port))

	def listen(self): # Listen for requests
		print("Listening on {}".format(self.proxy_port))
		while self.running:
			print "\nwaiting to receive message"
			try:
				data, address = self.socket.recvfrom(4096)
			except socket.error, e:
				print "Connection error"
				continue
			print "Received {} bytes from {}".format(len(data), address)
			if data:
				if data == "Close_Connection":
					self.running = False
				elif data == "Ping":
					self.socket.sendto("Pong", address)
				else:
					parsed_packet = self.parse_data(data)
					if parsed_packet:
						sent = self.socket.sendto("Echo", address)
						print "sent {} bytes back to {}".format(sent, address)
		print "WebSocketServer stopped"

	def parse_data(self, data):
		fields = data.split(MAGIC_SPLIT_CHAR)
		if len(fields) == 5:
			return {"src_ip":fields[0], "src_port":fields[1], "dst_ip":fields[2], "dst_port":fields[3], "data":fields[4]}
		else:
			return None
