#!/usr/bin/python2.7

import sys, os, getopt, subprocess, time
import socket, fcntl, struct

import logging ; logging.root.setLevel(logging.INFO) # s/INFO/DEBUG/ if you feel courious

# import ConfigParser, io # no way! openssl.cfg is NOT a valid INI file :(
# cf = ConfigParser.RawConfigParser()

sysconfig = '/etc/pki/tls/openssl.cnf'	# where "template" lives
anchors = '/etc/pki/ca-trust/source/anchors' # where that template wants to install
opensslcnf = '' # local copy

uc_conf_tpl = '/usr/share/instack-undercloud/undercloud.conf.sample' # template
uc_conf_lcl = 'undercloud.conf' # local one

values = {
	'public_api_ip': '192.0.2.2', # default, good enough
}

default_IP_addresses = [# defaults, don't change in case of any doubts
	'192.0.2.1',	#network_gateway
	'192.0.2.2',	#undercloud_public_vip
	'192.0.2.3',	#undercloud_admin_vip
	'192.0.2.4',	# reserved
]

default_host_names = [	# good as they are
	'undercloud_public_vip',
	'undercloud_admin_vip',
]

# you may want to change these lines:
req_distinguished_name = '''[req_distinguished_name]
countryName = Neverland
countryName_default = SU
stateOrProvinceName = Region 77
stateOrProvinceName_default = 77
localityName = Default City
localityName_default = Msk
organizationalUnitName = Intra
organizationalUnitName_default = Next
commonName = undercloud_public_vip
commonName_default = %(public_api_ip)s
commonName_max = 64
organizationName = The TesterZ
organizationName_default = z
'''

# don't change if you aren't pretty sure what you're doing
v3_req = '''[v3_req]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
'''

#-----------------------------------------------------------------------
# The code starts here
#


class Global:
	SE_level = None
	use_pause = False
#end class Global

G = Global()

class ConfigParser:
	'''Extremly relaxed parser of ini files.
	Somehow resembles to ConfigParser.RawConfigParser in its class API.
	'''

	def __init__(self):
		self.default_section = 'DEFAULT' # as it is in openssl.cnf
		self._filename = ''
		self.config = {self.default_section:{}}

	def read(self, *av):
		for filename in av:
			self._load(filename)

	def _line(self, line, section, line_no):
		if not line or line[0] == '#':
			return section
		if line[0] == '[':
			new_sec = line.split('[').pop(-1).split(']').pop(0).strip()
			if self.config.get(new_sec) is None :
				self.config[new_sec] = {}
			logging.debug('%s:%d:SEC:%s:%s', self._filename, line_no, new_sec, line)
			return new_sec
		if '#' in line :
			line = line.split('#').pop(0)
		if '=' not in line :
			logging.warn('Line #%d in file "%s" has no "=".', line_no, self._filename)
			return section
		name, value = line.split('=', 1)
		logging.debug('%s:%d:VAL:%s=%s', self._filename, line_no, name.strip(), value.strip())
		self.config[section][name.strip()] = value.strip()
		return section

	def _load(self, filename):
		self._filename = filename
		section = self.default_section
		fp = open(filename)
		n = 0
		for line in fp.xreadlines():
			n += 1
			section = self._line(line.strip(), section, n)
		fp.close()
		logging.debug('config: %s', repr(self.config))

	def raw_get(self, sec, var):
		'''Returns the *raw* value of entry 'var' from section 'sec'.
		'''
		return self.config.get(sec, self.config.get(self.default_section,{})).get(var)

	def get(self, section, name):
		'''Like .raw_get() but deals with "$name" substitutions.
		'''
		value = self.raw_get(section, name)
		while '$' in value :
			i = value.index('$') + 1
			v = ''
			while i < len(value) and good_char(value[i]):
				v += value[i]
				i += 1
			r = self.get(section, v)
			value = value.replace('$'+v, r)
		return value
# end class ConfigParser

cf = ConfigParser()
ucf = ConfigParser() # undercloud config

def error(rc, msg):
	'''Terminate execution on a fatal error.
	'''
	logging.fatal('ERROR(%d): %s\n' % (rc, msg))
	sys.exit(rc)

def run(*av, **kw):
	'''Run a shell command, break on non-zero return code.
	'''
	rc = subprocess.call(av)
	logging.debug('Command [%s] rc=%d', ' '.join(av), rc)
	if rc :
		error(rc, kw.get('msg', 'Command failed [%s]') % (' '.join(av),))

def output(*av, **kw):
	# kw['stderr'] = subprocess.STDOUT
	args = [] # one may use ['/bin/sh','-c',' '.join(av) + ';exit 0'] here...
	args += av
	logging.debug('Command [%s] captured', ' '.join(av))
	return apply(subprocess.check_output, (args,), kw)

def sudo(*av, **kw):
	'''Run a shell command as root, break on non-zero return code.
	'''
	kw['msg'] = kw.get('msg', 'Command failed (sudo) [%s]')
	if not av :
		av = ('-v',)
	apply(run, ('sudo',) + av, kw)

def openssl(*av, **kw):
	'''Run an OpenSSL command, break on non-zero return code.
	'''
	kw['msg'] = kw.get('msg', 'Command failed (openssl) [%s]')
	apply(run, ('openssl',) + av)

def root_openssl(*av, **kw):
	'''Run an OpenSSL command as root, break on non-zero return code.
	'''
	kw['msg'] = kw.get('msg', 'Command failed (sudo openssl) [%s]')
	apply(run, ('sudo', 'openssl',) + av, kw)

def SE_getenforce():
	'''Get SELinux enforcement setting.
	'''
	return output('sudo', 'getenforce').strip() == 'Enforcing'

def SE_setenforce(value=True):
	'''Set SELinux enforcement setting.
	'''
	logging.debug('SE_setenforce(%s)', `value`)
	if value is None :
		return
	sudo('setenforce', value and '1' or '0')

def exists(name):
	'''Assert existence of a file system object.
	'''
	if not os.path.exists(name):
		error(1, "No file '%s' exists." % (name,))

def rm(fname):
	'''Remove a file system object.
	'''
	if os.path.exists(fname):
		os.unlink(fname)

def root_rm(fname):
	'''Remove a file system object as root.
	'''
	if os.path.exists(fname):
		sudo('rm', '-f', fname)

def created(fname):
	'''Assert a file system object exists and has non-zero size.
	'''
	if os.path.exists(fname) and os.path.getsize(fname) > 0:
		logging.info('File "%s" created.' % (fname,))
	else:
		error(1, "File '%s' not created." % (fname,))

def load(fname):
	'''Read contents of a file.
	'''
	logging.debug('load(%s)', fname)
	fp = open(fname, 'rb')
	data = fp.read()
	fp.close()
	return data

def save(fname, data):
	'''Write data to a file.
	'''
	logging.debug('save(%s) %d bytes', fname, len(data))
	fp = open(fname, 'wb')
	fp.write(data)
	fp.close()

def copy(src, dst):
	'''Copy file contents.
	'''
	logging.debug('copy("%s", "%s")', src, dst)
	exists(src)
	save(dst, load(src))

def append_text(fname, data):
	'''Append data to the end of a file.
	'''
	logging.debug('append_text(%s) %d bytes', fname, len(data))
	fp = open(fname, 'ab')
	fp.write(data)
	fp.close()

def root_install(fname, path):
	'''Copy file to target as root.
	'''
	logging.debug('root_install("%s", "%s")', fname, path)
	exists(fname)
	if os.path.isdir(path):
		path += '/'
	sudo('cp', '-v', fname, path)

def pause(prompt=''):
	if G.use_pause:
		r = raw_input(prompt and prompt+': ' or '')

def gen_ca():
	'''Generate certificates for an "authority".
	'''
	logging.info('Generating CA')
	rm('ca.key.pem')
	openssl('genrsa',
		'-out','ca.key.pem',
		'4096')
	created('ca.key.pem')

	rm('ca.crt.pem')
	openssl('req',
		'-config', opensslcnf,
		'-key','ca.key.pem',
		'-new',
		'-x509',
		'-days','7300',
		'-extensions','v3_ca',
		'-out','ca.crt.pem')
	created('ca.crt.pem')

	pause('CA certs have been generated')

def root_mkpath(path):
	'''Create directory and all the path to it as root.
	'''
	if not os.path.exists(path+"/."):
		sudo('mkdir', '-p', path)
	if not os.path.exists(path+"/."):
		error(1, "Cannot mkdir '%s'." % (path,))

def mkpath(path):
	'''Create directory and all the path to it.
	'''
	if not os.path.exists(path+"/."):
		run('mkdir', '-p', path)
	if not os.path.exists(path+"/."):
		error(1, "Cannot mkdir '%s'." % (path,))

def install_ca():
	'''Install generated certificates for that "authority".
	'''
	logging.info('Installing CA')
	sudo()
	root_mkpath(anchors)
	root_install('ca.crt.pem', anchors)
	sudo('update-ca-trust', 'extract')

	pause('CA certs have been installed')

def comment_out(fname, section, mark='opnstk'):
	'''Comment out a section of an INI-type file
	with strings of '#'+mark+'#' form.
	'''
	lines = load(fname).split('\n')
	in_section = False
	for i in xrange(len(lines)):
		line = lines[i].rstrip()
		if not line:
			continue
		if in_section:
			if line[0] == '[':
				in_section = False
			else:
				lines[i] = '#'+mark+'#'+lines[i]
		else:
			if line[0] == '[':
				sec = line.split('[').pop(-1).split(']').pop(0).strip()
				if sec == section :
					in_section = True
					lines[i] = '#'+mark+'#'+lines[i]
	save(fname, '\n'.join(lines) + '\n')

def good_char(c):
	'''What we expect in an entry name.
	'''
	return c in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_'

def interface_enabled(sysfs_intf):
	enable = os.path.join(sysfs_intf, 'device/enable')
	return os.path.exists(enable) and load(enable).strip() == '1'

_interfaces = []
def sys_class_net_walker(check_enabled, path, names):
	'''This one will never dig in depth...
	'''
	while names :
		name = names.pop()
		if check_enabled :
			if not interface_enabled(os.path.join(path, name)):
				continue
		_interfaces.append(name)

def usort(lst):
	'''Sorta "sort -u $lst" operation. In-place.
	'''
	for e in lst[:] :
		while lst.count(e) > 1:
			lst.remove(e)
	lst.sort()

def list_interfaces(check_enabled=False):
	os.path.walk('/sys/class/net', sys_class_net_walker, check_enabled)
	return _interfaces[:]

def bytes23(string):
	if sys.version_info.major > 2 :
		return bytes(string, 'utf-8')
	return bytes(string)

def _intf2ip(intf):
	SIOCGIFADDR = 0x8915
	req = struct.pack('16sH14s', bytes23(intf[:15]), socket.AF_INET, b'\x00'*14)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	d = fcntl.ioctl(s.fileno(), SIOCGIFADDR, req) # Cannot assign requested address :(
	return socket.inet_ntoa(d[20:24])

def intf2ip(intf):
	w = output('ip', '-o', 'addr', 'show', 'dev', intf).split()
	if 'inet' in w :
		return w[w.index('inet') + 1].split('/').pop(0)

def list_host_addresses():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	s.connect(('<broadcast>', 0))
	ip = s.getsockname()[0] # at least one IP I'll grab here
	s.close()
	
	lst = [ip]
	for intf in list_interfaces():
		ip = intf2ip(intf)
		if ip is None or ip.startswith('127.') or ip in lst:
			continue
		lst.append(ip)
	usort(lst)
	return lst

def list_host_names():
	lst = [
		socket.gethostname(),
		socket.getfqdn(),
	]
	lst += list_host_addresses()
	usort(lst)
	return lst
			

def make_config():
	'''Create custom openssl.cfg using that one from /etc/pki/ as a template.
	'''
	global opensslcnf

	logging.info('Making config')

	cfg = os.path.basename(sysconfig)
	copy(sysconfig, cfg) # copy from template to local

	# disable these sections, if any
	comment_out(cfg, 'req_distinguished_name')
	comment_out(cfg, 'v3_req')
	comment_out(cfg, 'alt_names')

	# add our own versions for them
	append_text(cfg, req_distinguished_name % values)
	append_text(cfg, v3_req % values)

	alt_names = ['[alt_names]']

	ip_list = default_IP_addresses
	ip_list += list_host_addresses()
	usort(ip_list)

	dns_list = default_host_names
	dns_list += list_host_names()
	dns_list += ip_list
	usort(dns_list)

	logging.info('Adding more names and addresses:')
	i = 0
	for ip in ip_list :
		i += 1
		entry = 'IP.%d=%s' % (i, ip)
		logging.info('+ %s', entry)
		alt_names.append(entry)
	i = 0
	for name in dns_list :
		i += 1
		entry = 'DNS.%d=%s' % (i, name)
		logging.info('+ %s', entry)
		alt_names.append(entry)
	
	append_text(cfg, '\n'.join(alt_names) + '\n\n# EOF #\n')

	cf.read(cfg) # load the config built

	values['ca_sec'] = ca_sec = cf.get('ca', 'default_ca')
	logging.debug('ca.default_ca=%s', `ca_sec`)

	opensslcnf = cfg

	pause('OpenSSL config "%s" has been created' % (cfg,))

def check_undercloud_config():
	exists('undercloud.conf') # this one is built by your hands
	ucf.read('undercloud.conf') # load it

	# there are three things you'll probably change in 'undercloud.conf':
	# 1. undercloud_service_certificate=	where to put your cert
	# 2. image_path=			where to store images
	# 3. local_interface=			where to serve API on
	# because there is no AI to guess them right.

	srv_cert = ucf.get('DEFAULT', 'undercloud_service_certificate')
	logging.info('%s:undercloud_service_certificate=%s', ucf._filename, `srv_cert`)
	exists(os.path.dirname(srv_cert))	# you have to 'sudo mkdir' it first.

	image_path = ucf.get('DEFAULT', 'image_path')
	logging.info('%s:image_path=%s', ucf._filename, `image_path`)
	mkpath(image_path) # this is supposed to be in stack's home - no sudo

	local_interface = ucf.get('DEFAULT', 'local_interface')
	logging.info('%s:local_interface=%s', ucf._filename, `local_interface`)
	if not interface_enabled(os.path.join('/sys/class/net', local_interface)):
		error(1, "Local interface '%s' is not enabled", local_interface)

def check():
	'''Perform some preliminary checks.
	'''
	exists(sysconfig)
	check_undercloud_config()
	pause('Common check has been passed')

def root_touch(fname, data=''):
	'''Create an empty file (as root).
	'''
	if not os.path.exists(fname):
		aux = os.path.basename(fname)
		save(aux, data)
		root_install(aux, fname)
		rm(aux)

def fix_etc_files():
	# must perform some cleanup or even "sudo openssl ca ..." will fail :(
	ca_sec = values['ca_sec']

	dbf = cf.get(ca_sec, 'database')
	logging.debug('%s.database=%s', `ca_sec`, `dbf`)
	root_rm(dbf); root_touch(dbf) # clear the "database" (index.txt)
	root_rm(dbf+'.old')
	root_rm(dbf+'.attr')
	root_rm(dbf+'.attr.old')

	srl = cf.get(ca_sec, 'serial')
	logging.debug('%s.serial=%s', `ca_sec`, `srl`)
	root_rm(srl)
	root_rm(srl+'.old')
	root_touch(srl, '01\n') # reset serial, this is a "hex" value!

	pause('/etc/ files have been fixed')

def fix_ca_install():
	'''Polish out some misconceptions between RH's TFM and the observed nature.
	This includes indstallation of a cert copy to the path specified in config
	*along with* path given in the TFM ('private_key') as well as creation of
	some files where OpenSSL will expect to see them (see fix_etc_files too).
	'''
	logging.info('Fixing CA install...')
	ca_sec = values['ca_sec']

	created('ca.key.pem')	# pre-condition

	private_key = cf.get(ca_sec, 'private_key') # $dir/private/cakey.pem
	logging.debug('%s.private_key=%s', `ca_sec`, `private_key`)
	pk_dir = os.path.dirname(private_key)
	root_mkpath(pk_dir)
	root_install('ca.key.pem', private_key)

	pause('CA cert install have been fixed')

def gen_certs():
	'''Generate certificates for the server.
	'''
	logging.info('Generating certs...')

	rm('server.key.pem')
	rm('server.csr.pem')
	rm('server.crt.pem')

	openssl('genrsa', '-out', 'server.key.pem', '2048')
	created('server.key.pem')

	openssl('req', '-config', opensslcnf, '-key', 'server.key.pem', '-new',
		'-out', 'server.csr.pem')
	created('server.csr.pem')

	root_openssl('ca', '-config', opensslcnf, '-extensions', 'v3_req',
		'-days', '3650', '-in', 'server.csr.pem',
		'-out', 'server.crt.pem', '-cert', 'ca.crt.pem')
	created('server.crt.pem')

	pause('Server certs have been generated')

def install_certs():
	'''Install generated certificates for the server.
	'''
	logging.info('Installing certs...')

	created('ca.crt.pem')		# pre-conditions
	created('server.crt.pem')
	created('server.key.pem')

	# yes, two certs into a single file
	save('undercloud.pem', load('server.crt.pem') + load('server.key.pem'))
	created('undercloud.pem')

	root_mkpath('/etc/pki/instack-certs')
	root_install('undercloud.pem', '/etc/pki/instack-certs/.')
	sudo('semanage', 'fcontext', '-a', '-t', 'etc_t', '"/etc/pki/instack-certs(/.*)?"')
	sudo('restorecon', '-R', '/etc/pki/instack-certs')

	root_install('ca.crt.pem', anchors)
	sudo('update-ca-trust', 'extract')

	pause('Server certs have been installed')

def can_connect(addr, port):
	try:
		socket.create_connection((addr, port)).close()
		logging.debug('can_connect(%s, %s): True', `addr`, `port`)
		return True
	except:
		logging.debug('can_connect(%s, %s): False', `addr`, `port`)
		return False

def fetch(url):
	'''Try to fetch an URL via HTTPS with display of handhsking.
	'''
	logging.debug('fetch(%s) using curl', `url`)
	rc = subprocess.call(('curl', '-v', url)) # move to urllib2.urlopen() ??
	return rc == 0

def setup():
	G.SE_level = SE_getenforce()

def cleanup():
	logging.debug('CLEANUP start')
	SE_setenforce(G.SE_level)
	logging.debug('CLEANUP end')

def main():
	'''Just do the job.
	'''
	try:
		opts, args = getopt.getopt(
			sys.argv[1:],
			'?hpd',
			('help', 'pause', 'debug')
		)
		for o,v in opts:
			if o in ('-h', '--help'):
				print('-p, --pause -- stop after each step')
				print('-d, --debug -- use DEBUG level of logging')
				return 0
			elif o in ('-p', '--pause'):
				G.use_pause = True
			elif o in ('-d', '--debug'):
				logging.root.setLevel(logging.DEBUG)
	except getopt.error, why:
		print(why)
	else:
		pass
	for arg in args:
		pass

	setup()
	try:
		check()
		make_config()

		fix_etc_files()

		gen_ca()
		install_ca()

		fix_ca_install()

		gen_certs()
		install_certs()

		if can_connect(values['public_api_ip'], 13000):
			url = 'https://%(public_api_ip)s:13000/v3/auth/tokens' % values
			if not fetch(url):
				logging.warn('Will try haproxy restart')
				sudo('service', 'haproxy', 'restart')
				time.sleep(3)
				if not fetch(url):
					error(1, "Something went wrong with certs.")
		else:
			logging.warn('No listener at %s', '%(public_api_ip)s:13000' % values)
			run('service', 'haproxy', 'status')

		logging.info("You're lucky enough to get it done now.")
	finally:
		cleanup()

	print("""

Now you have to [re]run the 'openstack undercloud install' command!

Should the things go wrong, check'wm up with
	curl -v https://%(public_api_ip)s:13000/v3/auth/tokens
and then try to fix with
	service haproxy restart

""" % values)
	return 0

if __name__ == '__main__':
	sys.exit(main())
# EOF #
