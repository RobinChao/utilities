#!/bin/sh

has () {
	if test -x "$1"; then
		echo "# Has '$1'."
		return 0
	else
		echo "# ! No '$1'."
		return 1
	fi
}

run () {
	echo "# RUN [$@]"
	"$@" 2>&1
	echo "# Return Code [$?]"
}

divline () {
	echo '# ======================================================================'
	if test -n "$1"; then
		echo "# ==== $@ ===="
	fi
}

run_test () {
	local bin="$1"
	test -n "$bin" || return 1
	divline
	run "$@"
}

divline "Running as '$0'"
echo "# [[$0 $@]] #"

divline 'Tools available'

# /bin
has /bin/pwd	&& binpwd=/bin/pwd	|| binpwd=''
has /bin/uname	&& uname=/bin/uname	|| uname=''
has /bin/ping	&& ping=/bin/ping	|| ping=''
has /bin/netstat	&& netstat=/bin/netstat	|| netstat=''

# /sbin
has /sbin/ip		&& ip=/sbin/ip			|| ip=''
has /sbin/ifconfig	&& ifconfig=/sbin/ifconfig	|| ifconfig=''
has /sbin/route		&& route=/sbin/route		|| route=''
has /sbin/iptables	&& iptables=/sbin/iptables	|| iptables=''
has /sbin/iptables-save	&& iptsave=/sbin/iptables-save	|| iptsave=''
has /sbin/ethtool	&& ethtool=/sbin/ethtool	|| ethtool=''

# /usr/bin
has /usr/bin/apt-get	&& apt_get=/usr/bin/apt-get	|| apt_get=''
has /usr/bin/dpkg	&& dpkg=/usr/bin/dpkg		|| dpkg=''

# other
has /usr/sbin/arp && arp=/usr/sbin/arp || arp=''
test -z "$arp" && has /sbin/arp && arp=/sbin/arp

interfaces () {
	if test -n "$ip"; then
		"$ip" link | grep '^[0-9]\+:' | cut -d: -f2
	elif test -n "$ifconfig"; then
		"$ifconfig" -a | grep '^[^[:space:]]\+' | tr -s '[ \t]' '\t' | cut -f1
	else
		return 1
	fi
}

ethernets () {
	local eth=''
	for eth in `interfaces`; do
		run_test "$ethtool" "$eth"
	done
}

test_file () {
	local fname="$1"

	divline "$fname" file
	if test -f "$fname"; then
		ls -ldF "$fname" 2>&1 && cat -nvE "$fname"
	else
		echo "# ! No file '$fname'."
	fi
}

check_files () {
	local file=''

	for file in	/etc/network/interfaces \
			/etc/resolv.conf	\
			/etc/apt/sources.list	\
			/etc/os-release
	do
		test_file "$file"
	done
}

list_apt_hosts () {
	if test -f /etc/apt/sources.list; then
		grep '^deb' < /etc/apt/sources.list \
		| tr -s '[ \t]' '\t'  | cut -f2 | cut -d/ -f3 | sort -u
	fi
}

run_test 'pwd'
run_test "$binpwd"
run_test "$uname" -a

if [ -n "$dpkg" ]; then
	divline "Packages installed"
	dpkg -l | awk '($2=="openstack")||($2=="maas")||($2=="juju"){$1="";$4=":";print;}'
fi

check_files

run_test "$ip" link
run_test "$ip" addr
run_test "$ifconfig" -a
ethernets
run_test "$route" -n
run_test "$iptables" -L -n
run_test "$iptsave"
run_test "$arp" -n

run_test "$netstat" -A inet -anp

if test -n "$ping"; then
	for h in ntp.ubuntu.com pool.ntp.org `list_apt_hosts`; do
		run_test "$ping" -c5 -W2 "$h"
	done
fi

run_test "$apt_get" install -y --force-yes --allow-unauthenticated lldpd

run_test 'set' # environment

run_test "$dpkg" -l

divline 'The End'

# EOF #
