#!/usr/bin/python

import pyshark

import trollius as asyncio
from trollius import From, subprocess, Return
import os


import threading
import time
import signal

#Python 2/3 compat
try:
    import queue
except ImportError:
    import Queue as queue


#pyshark.tshark.tshark.force_tshark_path("./tshark_stub")

capture = pyshark.LiveCapture()
capture.set_debug()


xml_type = 'pdml'
parameters = ["./tshark_stub", '-n', '-T', xml_type] 

@asyncio.coroutine
def _get_tshark_process():
    tshark_process = yield From(asyncio.create_subprocess_exec(*parameters,
                                                                stdout=subprocess.PIPE,
                                                                stderr=open(os.devnull, "w"),
                                                                stdin=None))

    if tshark_process.returncode is not None and tshark_process.returncode != 0:
        raise TSharkCrashException(
            'TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))

    raise Return(tshark_process)


tshark_stub = asyncio.get_event_loop().run_until_complete(_get_tshark_process())


packet_times = queue.Queue()

def sniff():
	for p in capture._packets_from_tshark_sync(existing_process=tshark_stub):
		packet_times.put(time.time())
		print("sniffed packet")

thread = threading.Thread(target=sniff)
thread.daemon = True #this script will finish even if this thread has not.
thread.start()

def get():
	return packet_times.get(block=True,timeout=0.1)

assert packet_times.empty()

def send():
	sent_time = time.time()
	tshark_stub.send_signal(signal.SIGUSR1)
	return sent_time


def roundtrip():
	sent_time = send()

	try:
		a = get()
	except queue.Empty:
		print("Didn't Receive first packet in roundtrip")
		raise

	try:
		b = get()
	except queue.Empty:
		print("Didn't Receive second packet in roundtrip")
		raise

	t1 = a - sent_time
	t2 = b - sent_time

	print("Delay between packet send and receive is  " + str((t1,t2))  + " secs.")

time.sleep(.1)

try: 
	for i in range(10):
		roundtrip()
finally:
	pass
	#tshark_stub.kill()





