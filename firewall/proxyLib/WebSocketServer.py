#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, socket, threading
from select import select

MAGIC_SPLIT_CHAR = "_"
RUNNING = True

class ClientThread(threading.Thread):
	def __init__(self, config, address, data):
		threading.Thread.__init__(self)
		self.config = config
		self.address = address
		self.data = data
		print "[+] New thread started for {}:{}".format(address[0], address[1])
	def run(self):
		global RUNNING
		print "parsing {} bytes from {}".format(len(self.data), self.address)
		if self.data:
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			if (self.address[0] = self.config.get("connection", "kernel_ip")) and (self.address[1] = int(self.config.get("connection", "kernel_port"))):
				if self.data == "Close_Connection":
					RUNNING = False
				elif self.data == "Ping":
					sock.sendto("Pong", self.address)
			else:
				server_port = check_sysfs(self.address)
				if server_port == 20: # FTP
					if self.check_ftp(data):
						sock.sendto(data, self.address)
				elif server_port == 80: # HTTP
					if self.check_http(data):
						sock.sendto(data, self.address)
			sock.close()
	def check_sysfs(self, client_address):
		if not os.path.isfile(self.config.get("kernel", "sysfs_path")):
			print "sysfs {} does not exist.".format(self.config.get("kernel", "sysfs_path"))
			return 0
		if client_address[1] in [20, 21, 80]:
			print "Address {} belong to server and not client as expected.".format(client_address)
			return 0
		with open(self.config.get("kernel", "sysfs_path"), "r") as infile:
			kernel_connection_table = infile.readlines()
		for row in kernel_connection_table:
			cells = row.split("\t")
			if len(cells) == 4:
				if (cells[0] == client_address[0]) and (cells[1] == client_address[1]):
					return int(cells[3])
				elif (cells[2] == client_address[0]) and (cells[3] == client_address[1]):
					return int(cells[1])
		print "Client address does not exist inside the kernel connection table."
		return 0
	def check_http(self, data):
		split_pos = data.find("\r\n\r\n")
		if split_pos < 0:
			return False
		# Parse "Content-Length"
		content_length_pos = re.search("Content-Length:[ ]*([0-9]+)[\s\S]*?", data[:split_pos])
		if not content_length_pos:
			return False
		content_length_pos = int(content_length_pos.group(1))
		if content_length_pos <= 2000:
			return False
		# Parse magic numbers # Based on https://asecuritysite.com/forensics/magic & https://www.garykessler.net/library/file_sigs.html
		if data[split_pos+4:split_pos+8].encode("hex") == "2142444e": # OST, PAB, PST = "21 42 44 4E"
			return False
		elif data[split_pos+4:split_pos+12].encode("hex") == "d0cf11e0a1b11ae1": # DOC, DOT, PPS, PPT, XLA, XLS, WIZ = "D0 CF 11 E0 A1 B1 1A E1"
			return False
		elif data[split_pos+4:split_pos+8].encode("hex") == "504b0304": # DOCX, PPTX, XLSX = "50 4B 03 04"
			return False
		else:
			return True
	def check_ftp(self, data):
		# Parse magic numbers # Based on https://asecuritysite.com/forensics/magic & https://www.garykessler.net/library/file_sigs.html
		if data[:2].encode("hex") == "4d5a": # COM, DLL, DRV, EXE, PIF, QTS, QTX, SYS = "4D 5A"
			return False
		else:
			return True

class WebSocketServer(object):
	def __init__(self, config):
		global RUNNING
		self.config = config
		RUNNING = True # Keep serving requests
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.config.get("connection", "proxy_ip"), int(self.config.get("connection", "proxy_port"))))
		self.threads = []
	def listen(self): # Listen for requests
		global RUNNING
		print("Listening on {}".format(self.config.get("connection", "proxy_port")))
		while RUNNING:
			print "\nwaiting to receive message"
			try:
				data, address = self.socket.recvfrom(4096)
			except socket.error, e:
				print "Connection error"
				continue
			newthread = ClientThread(self.config, address, data)
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
