#!/usr/bin/python

import pyshark

pyshark.tshark.tshark.force_tshark_path("./tshark_stub")

capture = pyshark.LiveCapture()
capture.set_debug()

captured = []

for p in capture.sniff_continuously():
	print("sniffed packet")


