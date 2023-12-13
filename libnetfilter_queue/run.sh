#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <queueNum>"
    exit 1
fi

QUEUE_NUM=$1

read -p "Please enter the destination IP address you wish to allow ICMP packets for: " IP_ADDR

./libnetfilter_queue_icmp $QUEUE_NUM "$IP_ADDR"
