sudo iptables -X
sudo iptables -t filter -F
sudo iptables -P INPUT  ACCEPT
sudo iptables -P OUTPUT  ACCEPT
sudo iptables -P FORWARD  ACCEPT
