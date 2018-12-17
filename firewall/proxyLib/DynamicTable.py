#!/usr/bin/env python
# -*- coding: utf-8 -*-

class DynamicTable(object):
	def __init__(self, config):
		self.table = []

	def check_packet_struct(self, packet_struct):
		for entry in ["src_ip", "src_port", "dst_ip", "dst_port", "data"]:
			if entry not in packet_struct:
				return False
		return True

	def search(self, packet_struct):
		if not self.check_packet_struct(packet_struct):
			return None
		for recort in self.table:
			if recort["src_ip"] == packet_struct["src_ip"] &&
			   recort["src_port"] == packet_struct["src_port"] &&
			   recort["dst_ip"] == packet_struct["dst_ip"] &&
			   recort["dst_port"] == packet_struct["dst_port"]:
				return recort
		return None

	def insert(self, packet_struct):
		if not self.check_packet_struct(packet_struct):
			return False
		else:
			self.table.append(packet_struct)
			return True
