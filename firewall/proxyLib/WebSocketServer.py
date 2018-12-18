#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket, threading
from select import select
from proxyLib.DynamicTable import DynamicTable

MAGIC_SPLIT_CHAR = "_"
RUNNING = True

class ClientThread(threading.Thread):
	def __init__(self, dynamic_table, address, data):
		threading.Thread.__init__(self)
		self.dynamic_table = dynamic_table
		self.address = address
		self.data = data
		print "[+] New thread started for {}:{}".format(address[0], address[1])
	def run(self):
		global RUNNING
		print "parsing {} bytes from {}".format(len(self.data), self.address)
		if self.data:
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			if self.data == "Close_Connection":
				RUNNING = False
			elif self.data == "Ping":
				sock.sendto("Pong", self.address)
			else:
				parsed_packet = self.parse_data(self.data)
				if parsed_packet:
					if dynamic_table["src_port"] == 80 or dynamic_table["dst_port"] == 80:
						dynamic_table.search(parsed_packet) # TODO
					elif dynamic_table["src_port"] == 20 or dynamic_table["dst_port"] == 20:
						pass # TODO
					elif dynamic_table["src_port"] == 21 or dynamic_table["dst_port"] == 21:
						pass # TODO
					else: # XXX
						sent = sock.sendto("Echo", self.address) # XXX
						print "sent {} bytes back to {}".format(sent, self.address) # XXX
			sock.close()
	def parse_data(self, data):
		fields = data.split(MAGIC_SPLIT_CHAR)
		if len(fields) == 5:
			return {"src_ip":fields[0], "src_port":fields[1], "dst_ip":fields[2], "dst_port":fields[3], "data":fields[4]}
		else:
			return None

class WebSocketServer(object):
	def __init__(self, config):
		global RUNNING
		self.config = config
		self.proxy_ip = self.config.get("connection", "proxy_ip")
		self.proxy_port = int(self.config.get("connection", "proxy_port"))
		RUNNING = True # Keep serving requests
		self.dynamic_table = DynamicTable()
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.proxy_ip, self.proxy_port))
		self.threads = []
	def listen(self): # Listen for requests
		global RUNNING
		print("Listening on {}".format(self.proxy_port))
		while RUNNING:
			print "\nwaiting to receive message"
			try:
				data, address = self.socket.recvfrom(4096)
			except socket.error, e:
				print "Connection error"
				continue
			newthread = ClientThread(self.dynamic_table, address, data)
			newthread.start()
			self.threads.append(newthread)

		for t in self.threads:
			t.join()
		print "WebSocketServer stopped"
	def getRunning(self):
		global RUNNING
		return RUNNING
	def setRunning(self, value):
		global RUNNING
		RUNNING = value
