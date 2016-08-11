#!/bin/sh

ip=/sbin/ip
ifconfig=/sbin/ifconfig
route=/sbin/route
iptables=/sbin/iptables
iptsave=/sbin/iptables-save
ethtool=/sbin/ethtool
arp=''

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
has $binpwd || binpwd=''
has $uname || uname=''
has $ip || ip=''
has $ifconfig || ifconfig=''
has $route || route=''
has $iptables || iptables=''
has $iptsave || iptsave=''
has $ethtool || ethtool=''

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

netconfig () {
	local netconf=/etc/network/interfaces

	divline "$netconf" file
	if test -f "$netconf"; then
		ls -ldF "$netconf"
		cat -nvE "$netconf"
	else
		echo "# ! No '$netconf'."
	fi
}

run_test 'pwd'
run_test "$binpwd"
run_test "$uname" -a

netconfig
run_test "$ip" link
run_test "$ip" addr
run_test "$ifconfig" -a
ethernets
run_test "$route" -n
run_test "$iptables" -L -n
run_test "$iptsave"
run_test "$arp" -n

run_test 'set' # environment

divline 'The End'

# EOF #
