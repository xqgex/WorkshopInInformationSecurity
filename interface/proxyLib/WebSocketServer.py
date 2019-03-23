#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ast, os, re, socket, threading, urllib
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
			if (self.address[0] == self.config.get("connection", "kernel_ip")) and (self.address[1] == int(self.config.get("connection", "kernel_port"))):
				if self.data == "Close_Connection":
					RUNNING = False
				elif self.data == "Ping":
					sock.sendto("Pong", self.address)
			else:
				server_port = int(self.address[1])
				if server_port == 20: # FTP
					if self.check_ftp(self.data):
						sock.sendto(self.data, self.address)
				elif server_port == 25: # SMTP
					if self.check_smtp(self.data):
						sock.sendto(self.data, self.address)
				elif server_port == 80: # HTTP
					if self.check_http(self.data):
						sock.sendto(self.data, self.address)
			sock.close()
	def check_ftp(self, data):
		# Parse magic numbers # Based on https://asecuritysite.com/forensics/magic & https://www.garykessler.net/library/file_sigs.html
		if data[:2].encode("hex") == "4d5a": # COM, DLL, DRV, EXE, PIF, QTS, QTX, SYS = "4D 5A"
			return False
		else:
			return True
	def check_smtp(self, data):
		occurrences = [x.start() for x in re.finditer("Content-Disposition: attachment", data)]
		for occurrence in occurrences:
			loop_crlf = data[occurrence:].find("\n")
			if 0 < loop_crlf:
				loop_line = data[occurrence:occurrence+loop_crlf]
			else:
				loop_line = data[occurrence:]
			# Find the file name
			filename_pos = loop_line.find("filename")
			if 0 < filename_pos:
				quotation_marks = [x.start() for x in re.finditer("\"", loop_line[filename_pos:])]
				if 2 <= len(quotation_marks):
					loop_filename = loop_line[filename_pos+quotation_marks[0]+1:filename_pos+quotation_marks[1]]
					if loop_filename[-2:].lower() == ".c":
						return False # File extension is '.c'
		return True
	def check_http(self, data):
		split_pos = data.find("\r\n\r\n")
		if split_pos < 0:
			return False
		header_list = [x for x in data[:split_pos].split(" ") if len(x) > 0] # Split the header, ignore double spaces
		if len(header_list) < 2: # Invalid header
			return False
		# Parse "Content-Length"
		content_length_pos = re.search("Content-Length:[ ]*([0-9]+)[\s\S]*?", data[:split_pos])
		if not content_length_pos:
			return False # The request dosn't have Content-Length field
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
		if header_list[0].lower() == "get":
			# CVE-2018-14912 cgit directory traversal vulnerability, Avoid directory traversal by forbidding ".."
			path_unquoted = urllib.unquote(header_list[1]) # Convert '%2E' into '.'
			if ("/objects" in path_unquoted) and (".." in path_unquoted):
				return False
			# Check for c files
			if header_list[1].split("/")[-1].split("?")[0][-2:].lower() == ".c":
				return False # File extension is '.c'
		# The second test for c files
		if self.config.get("dlp", "advanced_test") == "true": # If the user has decided to enable the advanced test option
			content_type_pos = re.search("Content-Type:[ ]*([\/a-zA-Z]+)[\s\S]*?", data[:split_pos])
			if content_type_pos and content_type_pos.group(1) == "text/plain": # If the file is a simple text file, check for C language saved words
				for test_word in ast.literal_eval(self.config.get("dlp", "vocabulary")):
					if test_word in data[split_pos+4:]:
						return False
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
