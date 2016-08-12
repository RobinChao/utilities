#!/bin/sh -e
#
# MAAS Cluster/Rack Controller host setup
#
# copy the content of this script to /etc/rc.local or
# just call it from there
#

# ------------------------------->8------------------------------------
logger -t MaaS /etc/rc.local start

# if there is no DNS name server configured, provide one
if grep -q '^nameserver' /etc/resolv.conf; then
        logger -t MaaS /etc/rc.local nameserver: already
else
        echo 'nameserver 8.8.8.8' | resolvconf -a em1
        logger -t MaaS /etc/rc.local nameserver: added
fi

# you have to configure iptables to provide NAT & masquerading
if [ -f /etc/network/iptables.up.rules ]; then
        /sbin/iptables-restore /etc/network/iptables.up.rules
        logger -t MaaS /etc/rc.local iptables: loaded
else
        logger -t MaaS /etc/rc.local iptables: none
fi

# for some obscure reasons maas-proxy (squid3) doesn't start...
if service maas-proxy status | grep -q '^maas-proxy start/running'; then
        logger -t MaaS /etc/rc.local maas-proxy: already
else
        logger -t MaaS /etc/rc.local maas-proxy: starting
        service maas-proxy start
        sleep 5
        if service maas-proxy status | grep -q '^maas-proxy start/running'; then
                logger -t MaaS /etc/rc.local maas-proxy: started
        else
                logger -t MaaS /etc/rc.local maas-proxy: failed to start
        fi
fi

logger -t MaaS /etc/rc.local end
# ------------------------------->8------------------------------------

# EOF #
