#!/bin/bash

intf="$1" ; shift
if [ -z "$intf" ]; then
	echo "$(basename "$0") <interface> [<tcpdump options...>]">&2
	echo "Enabled interfaces:" >&2
	ip link | grep -w 'state UP' | cut -d: -f2 | cat -n >&2
	exit 1
fi

set -x
tcpdump -i "$intf" -s 1500 'port 67 or port 68' -e "$@"
# EOF #
