#!/bin/bash
###
_QUIET=yes
# process DROP list
function prepare_DROP {
	if [ -z "$(nft list table inet spamhaus 2>/dev/null)" ]; then
		nft add table inet spamhaus
	fi
	if [ -z "$(nft list set inet spamhaus drop_ipv4 2>/dev/null)" ]; then
		nft add set inet spamhaus drop_ipv4 '{ type ipv4_addr; flags interval, timeout; auto-merge; comment "SPAMHAUS dont route or peer"; }'
	else
		nft flush set inet spamhaus drop_ipv4
	fi
	if [ -z "$(nft list set inet spamhaus drop_ipv6 2>/dev/null)" ]; then
		nft add set inet spamhaus drop_ipv6 '{ type ipv6_addr; flags interval, timeout; auto-merge; comment "SPAMHAUS dont route or peer"; }'
	else
		nft flush set inet spamhaus drop_ipv6
	fi
	if [ -z "$(nft list chain inet spamhaus prerouting 2>/dev/null)" ]; then
		nft add chain inet spamhaus prerouting '{ type filter hook prerouting priority -100; }'
		nft add rule inet spamhaus prerouting 'ip saddr @drop_ipv4 counter drop'
		nft add rule inet spamhaus prerouting 'ip daddr @drop_ipv4 counter drop'
		nft add rule inet spamhaus prerouting 'ip6 saddr @drop_ipv6 counter drop'
		nft add rule inet spamhaus prerouting 'ip6 daddr @drop_ipv6 counter drop'
	fi
	if [ -z "$(nft list chain inet spamhaus postrouting 2>/dev/null)" ]; then
		nft add chain inet spamhaus postrouting '{ type filter hook postrouting priority 100; }'
		nft add rule inet spamhaus postrouting 'ip daddr @drop_ipv4 counter drop'
		nft add rule inet spamhaus postrouting 'ip6 daddr @drop_ipv6 counter drop'
	fi
}
function process_DROP {
	local _FILE=${1}
	# pump in the elements
	for IP in $( cat ${_FILE} | egrep -v '^;' | awk '{ print $1}' ); do
		if [[ "${IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]  ; then
			nft add element inet spamhaus drop_ipv4 \{ ${IP} timeout 72h \} 2>/dev/null
		else
			nft add element inet spamhaus drop_ipv6 \{ ${IP} timeout 72h \} 2>/dev/null
		fi
	done
}
# get DROP list
function get_DROP {
	[ -d /var/download/spamhaus ] || mkdir --parent /var/download/spamhaus
	wget ${_QUIET:+--quiet} -nd --timestamping --no-host-directories --no-parent --directory-prefix=/var/download/spamhaus https://www.spamhaus.org/drop/drop.txt
	if [ $? -eq 0 ]; then
		process_DROP /var/download/spamhaus/drop.txt
	else
		[ -z "${_QUIET}" ] && echo -e "INFO:\tnot updating nftables, wget returned error ($?)"
	fi
}
function get_DROPv6 {
	[ -d /var/download/spamhaus ] || mkdir --parent /var/download/spamhaus
	wget ${_QUIET:+--quiet} -nd --timestamping --no-host-directories --no-parent --directory-prefix=/var/download/spamhaus https://www.spamhaus.org/drop/dropv6.txt
	if [ $? -eq 0 ]; then
		process_DROP /var/download/spamhaus/dropv6.txt
	else
		[ -z "${_QUIET}" ] && echo -e "INFO:\tnot updating nftables, wget returned error ($?)"
	fi
}
# process DROP list
prepare_DROP
get_DROP
get_DROPv6
