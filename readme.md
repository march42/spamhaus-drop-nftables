# spamhaus-drop-nftables

Scripts to handle [Spamhaus.org](https://www.spamhaus.org/)
[do not route or peer lists (DROP)](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
with [netfilter](https://netfilter.org/) nftables.

## working concept

- blocking with nftables, family inet, table spamhaus
- works with IPv4 and IPv6
- load current DROP lists from Spamhaus
- prepare firewall table, chains, rules, ip_addr sets
- adding elements with timeout (72 hours)
- running the update daily via crontab

## usage

1. Make sure you have netfilter nftables and PHP 8.0-8.3 by running `nft --version` and `php --version`
1. Load the script to /usr/local/sbin
`curl --output-dir /usr/local/sbin --remote-name https://github.com/march42/spamhaus-drop-nftables/raw/refs/heads/main/spamhaus-drop.php`
2. Load the crontab to /etc/cron.d
`curl --output-dir /etc/cron.d --remote-name https://github.com/march42/spamhaus-drop-nftables/raw/refs/heads/main/spamhaus-drop.crontab`
3. Load and process `php /usr/local/sbin/spamhaus-drop.php --refresh`
4. Check the added ruleset `nft list table inet spamhaus`

Just running `php /usr/local/sbin/spamhaus-drop.php --refresh` will prepare the netfilter table first.

## netfilter

### ruleset

```
table inet spamhaus {
        set drop_ipv4 {
                type ipv4_addr
                flags interval,timeout
                auto-merge
                comment "SPAMHAUS do not route or peer"
                elements = {  }
        }
        set drop_ipv6 {
                type ipv6_addr
                flags interval,timeout
                auto-merge
                comment "SPAMHAUS do not route or peer"
                elements = {  }
        }
        chain prerouting {
                type filter hook prerouting priority -100; policy accept;
                ip saddr @drop_ipv4 counter drop
                ip daddr @drop_ipv4 counter drop
                ip6 saddr @drop_ipv6 counter drop
                ip6 daddr @drop_ipv6 counter drop
        }
        chain postrouting {
                type filter hook postrouting priority 100; policy accept;
                ip daddr @drop_ipv4 counter drop
                ip6 daddr @drop_ipv6 counter drop
        }
}
```

### explanation

- hold the IP address ranges in named sets (drop_ipv4, drop_ipv6)
- the named sets need flag interval, for holding network address ranges
- the flag timeout is needed, to expire the elements automatically (no need to flush elements, before loading)
- auto-merge should handle the error, when ranges are overlapping
- the actual drop is handled in the prerouting filter chain
- outgoing packets will be dropped at the postrouting filter chain

#### expiration and timeout

- the current elements get added with timeout 72 hours
- elements removed from the list will not get updated and expire after the 72 hour period
- without timeout the sets need to be flushed before adding elements

### commands

`nft delete table inet spamhaus`
Removes the table spamhaus with IP address sets and rule chains from netfilter firewall.
Stopps blocking traffic and opens the network.

`nft add table inet spamhaus`
Add table spamhaus to the inet family.

`nft add set inet spamhaus drop_ipv4 '{ type ipv4_addr; flags interval, timeout; auto-merge; comment "SPAMHAUS do not route or peer"; }'`
Add named set drop_ipv4 holding IPv4 addresses.

`nft add set inet spamhaus drop_ipv6 '{ type ipv6_addr; flags interval, timeout; auto-merge; comment "SPAMHAUS do not route or peer"; }'`
Add named set drop_ipv4 holding IPv6 addresses.

`nft add chain inet spamhaus prerouting '{ type filter hook prerouting priority -100; }'`
Add chain prerouting to table spamhaus.

`nft add rule inet spamhaus prerouting 'ip saddr @drop_ipv4 counter drop'`
Add rule to chain prerouting, drop if IPv4 source address in named set drop_ipv4 with counter.

`nft add rule inet spamhaus prerouting 'ip daddr @drop_ipv4 counter drop'`
Add rule to chain prerouting, drop if IPv4 destination address in named set drop_ipv4 with counter.

`nft add rule inet spamhaus prerouting 'ip6 saddr @drop_ipv6 counter drop'`
Add rule to chain prerouting, drop if IPv6 source address in named set drop_ipv6 with counter.

`nft add rule inet spamhaus prerouting 'ip6 daddr @drop_ipv6 counter drop'`
Add rule to chain prerouting, drop if IPv6 destination address in named set drop_ipv6 with counter.

`nft add element inet spamhaus drop_ipv4 '{ IPADDRESS timeout 72h }'`
Add element IPADDRESS (e.g. `143.49.0.0/16`) to named set drop_ipv4 with timeout 72 hours.

`nft list set inet spamhaus drop_ipv4`
List the named set.

`nft get element inet spamhaus drop_ipv4 { IPADDRESS }`
Check, if IPADDRESS (e.g. `143.49.123.123`) is element of the named set.

`nft list chain inet spamhaus prerouting`
List the prerouting filter chain in spamhaus table.

`nft list chain inet spamhaus postrouting`
List the postrouting filter chain in spamhaus table.

`nft list table inet spamhaus`
List the spamhaus ruleset.
Use option `--terse` omits the named set elements.

## configuration

*  SPAMHAUS_DROP_noIPV4
*  SPAMHAUS_DROP_noIPV6
*  SPAMHAUS_DROP_noTIMEOUT
*  SPAMHAUS_DROP_useCOUNTER

## work-to-do

- [ ] configuration handling
- [ ] check for IPv4 and/or IPv6
- [ ] do some error handling
- [ ] do more testing
- [ ] performance testing
