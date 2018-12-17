#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ConfigParser, io, os, signal, socket, sys, time
from threading import Thread
from proxyLib.WebSocketServer import WebSocketServer

CONFIG = None
CONFIG_FILE = "./proxyLib/proxy_configuration.ini"
SERVER = None

class config(object):
	def __init__(self):
		self.cache = {}
		self.config = ConfigParser.RawConfigParser(allow_no_value=True)
		self.load()
	def load(self):
		with open(CONFIG_FILE, "rb") as infile:
			our_config = infile.read()
		self.config.readfp(io.BytesIO(our_config))
	def get(self, section, option):
		if section in self.cache:
			if option not in self.cache[section]:
				self.cache[section][option] = self.config.get(section, option)
		else:
			self.cache[section] = {option:self.config.get(section, option)}
		return self.cache[section][option]

def signal_handler(signal, frame): # Add SIGINT handler for killing the threads
	global SERVER
	print(" Caught Ctrl+C, shutting down...")
	SERVER.running = False
	sys.exit()

def main():
	global CONFIG, SERVER
	signal.signal(signal.SIGINT, signal_handler)
	CONFIG = config() # Load configuration file
	SERVER = WebSocketServer(CONFIG)
	server_thread = Thread(target=SERVER.listen, args=[5])
	server_thread.daemon = True
	server_thread.start()
	while SERVER.running:
		time.sleep(10)
	print "Proxy server terminated"

if __name__ == "__main__":
	if os.name == "posix":
		main()
	else:
		print "[ERROR] Invalid OS, Only linux OS is supported"

