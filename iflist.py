#!/usr/bin/python2.7

import sys, socket, struct, fcntl, os
import ctypes

def _bytes23(string):
	py_ver = 100 * sys.version_info.major + sys.version_info.minor
	assert py_ver >= 207, 'Too old Python.'
	if py_ver >= 300 : # i.e. 3.0+
		return bytes(string, 'utf-8')
	return bytes(string)

def _dump(x):
	d = _bytes23(x)
	print('00'),
	for i in range(1, len(d)+1):
		print('%2d' % (i,)),
	print
	for b in d:
		print('%02x' % (ord(b),)),
	print

def _SIOCGIFCONF(req):
	SIOCGIFCONF = 0x00008912
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			d = fcntl.ioctl(s.fileno(), SIOCGIFCONF, req)
		except IOError:
			return None
	finally:
		s.close()
	return d

def intfconf(intf, default=None):
	# struct ifconf { int len; union { char *buf; struct ifreq *req; } };
	# ifconf = ctypes.create_string_buffer(4 + 8) # sizeof(int) + sizeof(char*)
	d = _SIOCGIFCONF(b'\x00'*12)
	print(`d`); _dump(d)
	return d # socket.inet_ntoa(d[20:24])

def intf2ip(intf, default=None):
	IFNAMSIZ = 16
	SIOCGIFADDR = 0x8915
	req = struct.pack(
		('%ds' % (IFNAMSIZ,))+'H'+'14s',
		_bytes23(intf[:15]),
		socket.AF_INET,
		b'\x00'*14,
	)
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			d = fcntl.ioctl(s.fileno(), SIOCGIFADDR, req)
		except IOError: # [Errno 99] Cannot assign requested address :(
			return default
	finally:
		s.close()
	return socket.inet_ntoa(d[20:24])

def lsintf(sysfs='/sys/class/net'):
	return os.listdir(sysfs)

def main():
	for intf in lsintf():
		print('%-15s %-15s' % (intf, intf2ip(intf, '-')))
		intfconf(intf)

if __name__ == '__main__':
	sys.exit(main())
# EOF #
