#!/usr/bin/python2.7

import sys, os, getopt, subprocess
import logging ; logging.root.setLevel(20)

# import ConfigParser, io # no way! openssl.cfg is NOT a valid INI file :(
# cf = ConfigParser.RawConfigParser()

sysconfig = '/etc/pki/tls/openssl.cnf'
anchors = '/etc/pki/ca-trust/source/anchors'
opensslcnf = ''

values = {
	'public_api_ip': '192.0.2.2',
}

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
v3_req = '''[v3_req]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
'''

class ConfigParser:
	'''Extremly relaxed parser of ini files.
	'''
	def __init__(self):
		self._filename = ''
		self.config = {'default':{}}
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
		section = 'default'
		fp = open(filename)
		n = 0
		for line in fp.xreadlines():
			n += 1
			section = self._line(line.strip(), section, n)
		fp.close()
		logging.debug('config: %s', repr(self.config))
	def get(self, sec, var):
		return self.config.get(sec, {}).get(var)
	def resolve(self, section, name):
		value = self.get(section, name)
		while '$' in value :
			i = value.index('$') + 1
			v = ''
			while i < len(value) and good_char(value[i]):
				v += value[i]
				i += 1
			r = cf.get(section, v)
			value = value.replace('$'+v, r)
		return value
# end class ConfigParser

cf = ConfigParser()
ucf = ConfigParser() # undercloud config

def error(rc, msg):
	logging.fatal('ERROR(%d): %s\n' % (rc, msg))
	sys.exit(rc)

def run(*av, **kw):
	rc = subprocess.call(av)
	logging.debug('Command [%s] rc=%d', ' '.join(av), rc)
	if rc :
		error(rc, kw.get('msg', 'Command failed [%s]') % (' '.join(av),))

def sudo(*av, **kw):
	kw['msg'] = kw.get('msg', 'Command failed (sudo) [%s]')
	if not av :
		av = ('-v',)
	apply(run, ('sudo',) + av, kw)

def openssl(*av, **kw):
	kw['msg'] = kw.get('msg', 'Command failed (openssl) [%s]')
	apply(run, ('openssl',) + av)

def root_openssl(*av, **kw):
	kw['msg'] = kw.get('msg', 'Command failed (sudo openssl) [%s]')
	apply(run, ('sudo', 'openssl',) + av, kw)

def exists(name):
	if not os.path.exists(name):
		error(1, "No file '%s' exists." % (name,))

def rm(fname):
	if os.path.exists(fname):
		os.unlink(fname)

def created(fname):
	if os.path.exists(fname) and os.path.getsize(fname) > 0:
		logging.info('File "%s" created.' % (fname,))
	else:
		error(1, "File '%s' not created." % (fname,))

def load(fname):
	logging.debug('load(%s)', fname)
	fp = open(fname, 'rb')
	data = fp.read()
	fp.close()
	return data

def save(fname, data):
	logging.debug('save(%s) %d bytes', fname, len(data))
	fp = open(fname, 'wb')
	fp.write(data)
	fp.close()

def copy(src, dst):
	logging.debug('copy("%s", "%s")', src, dst)
	exists(src)
	save(dst, load(src))

def append_text(fname, data):
	logging.debug('append_text(%s) %d bytes', fname, len(data))
	fp = open(fname, 'ab')
	fp.write(data)
	fp.close()

def root_install(fname, path):
	logging.debug('root_install("%s", "%s")', fname, path)
	exists(fname)
	if os.path.isdir(path):
		path += '/'
	sudo('cp', '-v', fname, path)

def gen_ca():
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

def root_mkpath(path):
	if not os.path.exists(path+"/."):
		sudo('mkdir', '-p', path)
	if not os.path.exists(path+"/."):
		error(1, "Cannot mkdir '%s'." % (path,))

def install_ca():
	logging.info('Installing CA')
	sudo()
	root_mkpath(anchors)
	root_install('ca.crt.pem', anchors)
	sudo('update-ca-trust', 'extract')

def comment_out(fname, section, mark='opnstk'):
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
	return c in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_'


def make_config():
	global opensslcnf

	logging.info('Making config')
	cfg = os.path.basename(sysconfig)
	copy(sysconfig, cfg)
	comment_out(cfg, 'req_distinguished_name')
	comment_out(cfg, 'v3_req')
	comment_out(cfg, 'alt_names')
	append_text(cfg, req_distinguished_name % values)
	append_text(cfg, v3_req % values)
	alt_names = ['[alt_names]']
	# IP.n = ...
	# DNS.n = ...
	alt_names += ['IP.1=192.0.2.1','IP.2=192.0.2.2','DNS.1=undercloud_public_vip','DNS.2=opt-03']
	append_text(cfg, '\n'.join(alt_names) + '\n\n# EOF #\n')

	cf.read(cfg)

	ca_sec = cf.get('ca', 'default_ca')
	values['ca_sec'] = ca_sec
	logging.debug('ca.default_ca=%s', `ca_sec`)

	opensslcnf = cfg


def check():
	exists(sysconfig)

def fix_ca_install():
	logging.info('Fixing CA install...')
	ca_sec = values['ca_sec']

	private_key = cf.resolve(ca_sec, 'private_key') # $dir/private/cakey.pem
	logging.debug('%s.private_key=%s', `ca_sec`, `private_key`)

	pk_dir = os.path.dirname(private_key)
	root_mkpath(pk_dir)
	root_install('ca.key.pem', private_key)

	dbf = cf.resolve(ca_sec, 'database')
	logging.debug('%s.database=%s', `ca_sec`, `dbf`)
	if not os.path.exists(dbf):
		dbn = os.path.basename(dbf)
		save(dbn, '')
		root_install(dbn, dbf)
		rm(dbn)
	if not os.path.exists(dbf+'.attr'):
		dbn = os.path.basename(dbf+'.attr')
		save(dbn, '')
		root_install(dbn, dbf+'.attr')
		rm(dbn)

def gen_certs():
	logging.info('Generating certs...')

	openssl('genrsa', '-out', 'server.key.pem', '2048')
	created('server.key.pem')

	openssl('req', '-config', opensslcnf, '-key', 'server.key.pem', '-new',
		'-out', 'server.csr.pem')
	created('server.csr.pem')

	root_openssl('ca', '-config', opensslcnf, '-extensions', 'v3_req',
		'-days', '3650', '-in', 'server.csr.pem',
		'-out', 'server.crt.pem', '-cert', 'ca.crt.pem')
	created('server.crt.pem')

def install_certs():
	logging.info('Installing certs...')
	save('undercloud.pem', load('server.crt.pem') + load('server.key.pem'))
	root_mkpath('/etc/pki/instack-certs')
	root_install('undercloud.pem', '/etc/pki/instack-certs/.')
	sudo('semanage', 'fcontext', '-a', '-t', 'etc_t', '"/etc/pki/instack-certs(/.*)?"')
	sudo('restorecon', '-R', '/etc/pki/instack-certs')

	root_install('ca.crt.pem', anchors)
	sudo('update-ca-trust', 'extract')

def main():
	try:
		opts, args = getopt.getopt(
			sys.argv[1:],
			'?h',
			('help',)
		)
		for o,v in opts:
			if o in ('-h', '--help'):
				print('HELP!')
				return 0
	except getopt.error, why:
		print(why)
	else:
		pass
	for arg in args:
		pass

	check()
	make_config()

	gen_ca()
	install_ca()

	fix_ca_install()

	gen_certs()
	install_certs()

	ucf.read('undercloud.conf')
	srv_cert = ucf.get('DEFAULT', 'undercloud_service_certificate')
	logging.info('%s:undercloud_service_certificate=%s', ucf._filename, `srv_cert`)
	exists(srv_cert)

	return 0

if __name__ == '__main__':
	sys.exit(main())
# EOF #
