#!/bin/bash

cat >/dev/tty <<-EOT

	# This scipt will check network config of a MAAS Controller node.
	# It should be ran on a MAAS Controller Node.
	# Follow the advises, if any.
	# Run again until no advises shown.
	# The script will NOT change anything.

EOT

eth0='' # 'eno1'	# external
eth1='' # 'enp12s0f2'	# internal

ntp_host='ntp.ubuntu.com'

interfaces='/etc/network/interfaces'
sysctl='/etc/sysctl.conf'

all_ok='yes'
everything_done='no'
declare -a messages=()

tempFile=$(mktemp --tmpdir=/tmp)
cleanup () {
	rm -f "$tempFile"

	message_summary > /dev/tty
}
trap cleanup EXIT

message_summary () {
	local -i i=0
	local c='completed'

	echo "========================================================================"
	if [ "$everything_done" != 'yes' ]; then
		c="aborted"
	fi
	echo "=== Check ($c) summary:"
	for ((i=0; i<${#messages[*]}; i++)); do
		local m="${messages[$i]}"
		printf '%3d: %s\n' $((i+1)) "$m"
	done
	echo "========================================================================"
}

add_message () {
	local m=$(echo "$@")
	messages[${#messages[*]}]="$m"
	echo "$m"
}

error () {
	local -i rc=$1
	shift
	all_ok='no'
	add_message "ERROR: $@" >&2
	exit $rc
}

good () {
	add_message "GOOD: $@" >&1
}

info () {
	add_message "INFO: $@" >&1
}

note () {
	add_message "NOTE: $@" >&1
}

warn () {
	all_ok='no'
	add_message "WARNING: $@" >&1
}

where () {
	type -p "$1" 2>/dev/null
}

netcat=$(where "nc") || netcat=''

ip=$(where "ip") || error 1 "No 'ip' (install iproute2)."
ifconfig=$(where "ifconfig") || error 1 "No 'ifconfig' (install net-tools)."
route=$(where "route") || error 1 "No 'route' (install net-tools)."
iptables=$(where "iptables") || error 1 "No 'iptables' (install iptables)."
ethtool=$(where "ethtool") || error 1 "No 'ethtool' (install ethtool)."

has_access_to () {
	[ -n "$netcat" -a -x "$netcat" ] && $netcat -vzw1 "$@"
}

intf_list () {
	$ifconfig -s | awk 'NR>1{print $1;}'
}

intf_addrs () {
	local intf="$1"
	$ip addr show dev "$intf" \
	| grep -o 'inet [0-9.]\+' \
	| cut -d' ' -f2
}

intf_list_long () {
	local i='' a=''

	while read i; do
		a=$(intf_addrs "$i" | tr -s '[:space:]' ' ')
		a=$(echo $a)
		echo -e "$i ($a)"
	done < <(intf_list)
}

select_except () {
	# read words (lines) from stdin
	# make selection of words
	# except given on command line
	local -a words=()
	local w='' t='' x='' ok=''
	while read w t; do
		ok='yes'
		for x in "$@"; do
			if [ "$w" = "$x" ]; then
				ok='no'
				break
			fi
		done
		if [ "$ok" = 'yes' ]; then
			words[${#words[*]}]="$w $t"
		fi
	done
	select w in "${words[@]}"; do
		if [ -z "$w" ]; then
			read -p 'Terminate? ' w </dev/tty
			case "$w" in
			yes)	error 0 "Terminated.";;
			*)	echo "ok">&2; continue;;
			esac
		fi
		echo "$w" | cut -d' ' -f1
		return
	done </dev/tty
}

intf_is_slice () {
	local intf="$1"
	echo "/$intf/" | grep -q '^/.\+:.\+/$'
}

intf_base () {
	local intf="$1"
	local base=$($ip link show dev "$intf" | head -n1 | cut -d: -f2)
	echo $base
}

intf_up () {
	local intf="$1"
	$ip addr show dev "$intf" | head -n1 | grep -wq 'state UP'
}

link_up () {
	local intf="$1"
	local link=$($SUDO $ethtool "$intf" 2>/dev/null | grep '^[[:space:]]\+Link detected: yes$')
	test -n "$link"
}

intf_ok () {
	local intf="$1" addrs=''

	[ -z "$intf" ] && return 1
	addrs=$(intf_addrs "$intf")
	[ -z "$addrs" ] && { warn "Interface '$intf' has no IP."; return 1; }
	intf_list | grep -wq "^$intf\$" || return 1
	intf_is_slice "$intf" && { warn "Subinterface '$intf' may NOT be used for MAAS!"; return 1; }
	intf_up "$intf" || { warn "Interface '$intf' is DONW."; return 1; }
	link_up "$intf" || { warn "Link '$intf' is DONW."; return 1; }
}

private_ip () {
	local ipaddr="$1" # 10/8, 172.16/12, 192.168/16 -- RFC 1918

	case "$ipaddr" in
	10.*.*.*)	return 0;;
	172.16.*.*|172.17.*.*|172.18.*.*|172.19.*.*) return 0;;
	172.20.*.*|172.21.*.*|172.22.*.*|172.23.*.*) return 0;;
	172.24.*.*|172.25.*.*|172.26.*.*|172.27.*.*) return 0;;
	172.28.*.*|172.29.*.*|172.30.*.*|172.31.*.*) return 0;;
	192.168.*.*)	return 0;;
	esac
	return 1
}

link_local_ip () {
	local ipaddr="$1" # 169.254/16 minus the first and the last /24 subnetes RFC 6890, 3927

	case "$ipaddr" in
	169.254.0.*|169.254.255.*)	return 2;; ## ERROR ???
	169.254.*.*) return 0;;
	esac
	return 1
}

quote_all_words () {
	sed -e "1,\$s/[^ ]\+/'&'/g"
}

output_has_word () {
	local word="$1"
	local mesg="$2"
	shift 2

	if $@ | grep -q '[[:space:]]\+'$word'[[:space:]]\+'; then
		echo "# It looks like $mesg for '$word' is ok."
	else
		warn "No '$word' in $mesg."
		return 1
	fi
}

must_have_service () {
	local service="$1"
	local file="/lib/systemd/system/$service.service"

	[ -e "$file" ] || {
		note "There is no service file '$file'."
		note "This may be an unsupported distro."
		return
	}
	$SUDO service "$service" status >"$tempFile" 2>&1 \
		|| error 1 "You must have '$service' \"service\": $(< $tempFile)"
	grep '^'$service'[[:space:]]\+start/running' < "$tempFile" \
		|| error 1 "Please start '$service' \"service\": $(< $tempFile)"
	good "$service is up and running."
}

[ -f "$interfaces" ] || error 1 "No '$interfaces' - wrong distriution."

#

if [ -w /etc/passwd ]; then
	SUDO=''
else
	SUDO='sudo'
	info "Using '$SUDO'." >&2
	$SUDO -v
	echo
fi

if ! intf_ok "$eth0"; then
	echo "# Please, select _external_ interface (type number):" >&2
	eth0=$(intf_list_long | select_except $eth0 $eth1)
	test -n "$eth0" || error 1 "No external interface '$eth0'."
	intf_ok "$eth0" || error 1 "External interface '$eth0' is unusable."
fi

if ! intf_ok "$eth1"; then
	echo "# Please, select _internal_ interface (type number):" >&2
	eth1=$(intf_list_long | select_except $eth0 $eth1)
	test -n "$eth1" || error 1 "No external interface '$eth1'."
	intf_ok "$eth1" || error 1 "Internal interface '$eth1' is unusable."
fi

info "External link via '$eth0' ($(intf_addrs "$eth0"))."
$ifconfig "$eth0" || error $? "No interface '$eth0'."
$SUDO $ethtool "$eth0" || error $? "No link '$eth0'."

info "Internal link via '$eth1' ($(intf_addrs "$eth1"))."
$ifconfig "$eth1" || error $? "No link '$eth1'."
$SUDO $ethtool "$eth1" || error $? "No link '$eth1'."

echo "# System-wide interface config ($interfaces):"

intf_stanza () {
	case "$1" in
	esac
	return 1
}

eth0_found=''; eth0_dns=''; eth0_addr=''
eth1_found=''; eth1_dns=''; eth1_addr=''

check_ifconfig () {
# TODO
# 1. the external interface should be taken up _before_ the internal one
# 2. the external interface should have resolver configured (dns_nameservers)
#
	local interfaces="$1"
	local k='' a='' t='' idx='_'
	local -i line=0

	while read k a t; do
		let line+=1
		case "$k" in
		mapping)
			case "$a" in
			"$eth0"*)	[ -z "$eth0_found" ] && eth0_found=$line; idx=0 ;;
			"$eth1"*)	[ -z "$eth1_found" ] && eth1_found=$line; idx=1 ;;
			*)		idx='x' ;;
			esac
			echo -e "$idx|\t$k $a $t" ;;
		iface|auto|allow-*)
			case "$a" in
			"$eth0")	[ -z "$eth0_found" ] && eth0_found=$line; idx=0
					echo -e "$idx=$a\t@$line"
					;;
			"$eth1")	[ -z "$eth1_found" ] && eth1_found=$line; idx=1
					echo -e "$idx=$a\t@$line"
					;;
			*)		idx='x' ;;
			esac
			echo -e "$idx:\t$k $a $t" ;;
		source)
			echo -e "$idx:\t$k $a $t"
			for t in $a; do
				[ -r "$t" ] && check_ifconfig "$t"
			done;;
		source-directory)
			echo -e "$idx:\t$k $a $t"
			for t in $a/*; do
				[ -r "$t" ] && check_ifconfig "$t"
			done;;
		*)
			echo -n -e "$idx:\t$k $a $t"
			case "$k" in
			dns-nameservers)
				case "$idx" in
				0|1)	echo -n -e "\t# <good>"
					eval "eth${idx}_dns=$line"
					;;
				*)	;;
				esac
				;;
			address)
				case "$idx" in
				0|1)	echo -n -e "\t# <good>"
					if echo "$a" | grep -q '^[0-9.]\+/[0-9]\+$'; then
						a=$(echo $a|cut -d/ -f1)
					fi
					eval "eth${idx}_addr=$a"
					;;
				*)	;;
				esac
				;;
			*)
				;;
			esac
			echo
			;;
		esac
	done < <(grep -v '^#' "$interfaces" | cut -d\# -f1 | grep -v '^[ ]*$')
}

check_ifconfig "$interfaces"

[ -z "$eth0_found" ] && warn "No config for external '$eth0'."
[ -z "$eth1_found" ] && warn "No config for internal '$eth1'."

[ -z "$eth0_addr" ] && warn "No IP address configured for external '$eth0'."
[ -z "$eth1_addr" ] && warn "No IP address configured for internal '$eth1'."

private_ip "$eth0_addr" && note "External '$eth0' is using private IP '$eth0_addr'."
private_ip "$eth1_addr" || warn "Internal '$eth1' is using non-private IP '$eth1_addr'."

[ -z "$eth0_dns" ] && warn "No DNS config for external '$eth0'."
[ -z "$eth1_dns" ] && note "No DNS config for internal '$eth1'."

link_local_ip "$eth0_addr" && error 1 "Link-local IP on external '$eth0'."
link_local_ip "$eth1_addr" && error 1 "Link-local IP on internal '$eth1'."

(( $eth0_found > $eth1_found )) \
	&& warn "You may want to have external '$eth0' configured before internal '$eth1'."
good "Interfaces '$eth0' (external) and '$eth1' (internal) somehow configured."
echo

# base interfaces, if any
eth0b=$(intf_base "$eth0")
eth1b=$(intf_base "$eth1")

echo "# Local routing:"
$route -n
$route -n | grep -q "[[:space:]]\+$eth0b\$" || error 1 "Interface '$eth0' is never used."
$route -n | grep -q "[[:space:]]\+$eth1b\$" || error 1 "Interface '$eth1' is never used."
good "Both interfaces are in use."
echo

echo "# Local NAT config:"
W=''
$SUDO $iptables -S -t nat
output_has_word "$eth0" 'NAT config' "$SUDO $iptables -S -t nat" || W='yes'
if [ "$W" = 'yes' ]; then
	warn "You may have troubles with external connectivity for deployed machines."
	cat >&2 <<-EOT
		# Consider adding these rules:
		# -t nat -A POSTROUTING -o $eth0 -j MASQUERADE

EOT
fi
$SUDO $iptables -t nat -S POSTROUTING | grep -qw MASQUERADE \
	|| error 1 "No MASQUERADE rule in POSTROUTING chain (table 'nat')."
echo

echo "# Kernel support for NAT:"
n=$($SUDO find /sys/module/ -name '*_nat*' -exec ls -ld {} \; | grep -v /holders/ | wc -l)
(( $n == 0 )) && error 1 "No NAT kernel support found." || good "Kernel has modules."

lsmod | grep nat_ && good "NAT modules loaded." || warn "No NAT kernel modules loaded."
echo

echo "# Local forwarding policy:"
W=''
$SUDO $iptables -S FORWARD
output_has_word "$eth0" 'routing' "$SUDO $iptables -S FORWARD" || W='yes'
output_has_word "$eth1" 'routing' "$SUDO $iptables -S FORWARD" || W='yes'
if [ "$W" = 'yes' ]; then
	warn "You may not have external connectivity for deployed machines."
	cat >&2 <<-EOT
		# Consider adding these rules:
		# -A FORWARD -i $eth0 -o $eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
		# -A FORWARD -i $eth1 -o $eth0 -j ACCEPT
EOT
else	good "Local forwarding looks set up."
fi
echo

grep -Hn 'net.ipv4.ip_forward[[:space:]]*=[[:space:]]*1' "$sysctl" \
	|| error 1 "You must add 'net.ipv4.ip_forward=1' to '$sysctl'."
grep -q '#[[:space:]]*net.ipv4.ip_forward[[:space:]]*=[[:space:]]*1' "$sysctl" \
	&& error 1 "You must uncomment the line and reload with '$SUDO sysctl -p'."

cut -d\# -f1 /etc/resolv.conf | grep -qw '^nameserver' \
	|| error 1 "No nameserver configured. Run \`echo nameserver 8.8.8.8|resolvconf -a '$eth0'\`."

must_have_service maas-rackd
must_have_service maas-clusterd
must_have_service maas-regiond
must_have_service maas-dhcpd
must_have_service maas-proxy
$SUDO netstat -A inet -anp | grep /squid
echo

# check for some files 
for file in /usr/share/maas/maas/urls.py; do
	[ -f "$file" ] || error 1 "MaaS installed in a wrong way: no '$file' file."
done
good 'MaaS install looks ok.'
echo

if [ -n "$netcat" ]; then
	echo
	has_access_to -u "$ntp_host" 123 || error 1 "NTP host '$ntp_host' unreachable."
	good "NTP server '$ntp_host' looks ok."
	has_access_to -u "pool.ntp.org" 123 && good "You may use 'pool.ntp.org' for NTP."

# TODO check for IPMI access. Figure out how to find HMC addresses...
#	ipmi='no'
#	for a in $(intf_addrs "$eth0") $(intf_addrs "$eth1"); do
#		if has_access_to -u $a 623; then
#			ipmi='yes'
#			good "Can access IPMI on '$a'."
#		else
#			note "No IPMI access on '$a'."
#		fi
#	done
#	[ "$ipmi" = 'no' ] && warn "No access to IPMI."
else
	warn "Cannot check NTP and IPMI availability."
fi
echo

everything_done='yes'
echo
[ "$all_ok" = 'yes' ]	&& echo "# Congrats! It looks like everything is fine!" \
			|| echo "WARNING: Check your network config!" >&2
# EOF #
