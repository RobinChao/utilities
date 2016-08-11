#!/bin/sh

ip=/sbin/ip
ifconfig=/sbin/ifconfig
route=/sbin/route
iptables=/sbin/iptables
iptsave=/sbin/iptables-save
ethtool=/sbin/ethtool
arp=''
apt_get=/usr/bin/apt-get
ping=/bin/ping

binpwd=/bin/pwd
uname=/bin/uname

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
has $binpwd	|| binpwd=''
has $uname	|| uname=''
has $ip		|| ip=''
has $ifconfig	|| ifconfig=''
has $route	|| route=''
has $iptables	|| iptables=''
has $iptsave	|| iptsave=''
has $ethtool	|| ethtool=''
has $apt_get	|| apt_get=''
has $ping	|| ping=''

has /sbin/arp && arp=/sbin/arp
has /usr/sbin/arp && arp=/usr/sbin/arp

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
			/etc/apt/sources.list
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

check_files

run_test "$ip" link
run_test "$ip" addr
run_test "$ifconfig" -a
ethernets
run_test "$route" -n
run_test "$iptables" -L -n
run_test "$iptsave"
run_test "$arp" -n

if test -n "$ping"; then
	for h in ntp.ubuntu.com pool.ntp.org `list_apt_hosts`; do
		run_test "$ping" -c5 -W2 "$h"
	done
fi

run_test "$apt_get" --yes --force-yes lldpd

run_test 'set' # environment

divline 'The End'

# EOF #
