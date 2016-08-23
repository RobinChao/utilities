#!/usr/bin/python2.7

import sys, socket, struct, fcntl, os

def _bytes23(string):
	py_ver = 100 * sys.version_info.major + sys.version_info.minor
	assert py_ver >= 207, 'Too old Python.'
	if py_ver >= 300 : # i.e. 3.0+
		return bytes(string, 'utf-8')
	return bytes(string)

def intf2ip(intf, default=None):
	SIOCGIFADDR = 0x8915
	req = struct.pack('16sH14s', _bytes23(intf[:15]), socket.AF_INET, b'\x00'*14)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		d = fcntl.ioctl(s.fileno(), SIOCGIFADDR, req)
	except IOError: # [Errno 99] Cannot assign requested address :(
		return default
	return socket.inet_ntoa(d[20:24])

def lsintf(sysfs='/sys/class/net'):
	return os.listdir(sysfs)

def main():
	for intf in lsintf():
		print('%-15s %-15s' % (intf, intf2ip(intf, '-')))

if __name__ == '__main__':
	sys.exit(main())
# EOF #
