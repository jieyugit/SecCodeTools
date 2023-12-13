##! /bin/sh
iptables -t filter -I INPUT -p icmp -j ACCEPT
iptables -t filter -I OUTPUT -p icmp -j ACCEPT
iptables -P INPUT  DROP
iptables -P  OUTPUT  DROP

iptables -t filter -I INPUT -p tcp --dport 22 -j REJECT
