##! /bin/sh

iptables -t filter -F

iptables -t filter -I INPUT -p tcp --dport 22 -j ACCEPT
iptables -t filter -I OUTPUT -p tcp --sport 22 -j ACCEPT

iptables -t filter -A OUTPUT -p icmp -j DROP

iptables  -P INPUT DROP
iptables  -P OUTPUT ACCEPT
iptables  -P FORWARD DROP
