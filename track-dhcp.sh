#!/bin/bash

echo "$(basename "$0") will track BOOTP/DHCP activity on the specified/selected interface.">&2
echo >&2

intf="$1" ; shift
if [ -z "$intf" ]; then
	echo "$(basename "$0") [-i | <interface>] [<tcpdump options...>]">&2
	echo "Enabled interfaces:" >&2
	ip link | grep -w 'state UP' | cut -d: -f2 | cat -n >&2
	exit 1
elif [ "$intf" = '-i' ]; then
	echo "Enabled interfaces:" >&2
	select intf in `ip link | grep -w 'state UP' | cut -d: -f2`; do
		[ -n "$intf" ] && break
	done
fi

log="${intf}.tcpdump"

[ -f "$log" ] && { echo >> "$log"; echo '==========' >> "$log"; }
date '+%F %T' >> "$log"

set -x
tcpdump -i "$intf" -s 1500 'port 67 or port 68' -e "$@" | tee -a -i "$log"
# EOF #
