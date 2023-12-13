#!/bin/bash

# This script adds an iptables rule to direct incoming packets to NFQUEUE.

# Check for root privileges
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi

# Check if queue number is provided as an argument
if [ "$#" -eq 1 ]; then
    QUEUE_NUM=$1
else
    # Prompt the user to enter the queue number
    read -p "Please enter the queue number for NFQUEUE: " QUEUE_NUM
fi

# Add the iptables rule
iptables -I INPUT -j NFQUEUE --queue-num "${QUEUE_NUM}"

# Check if the iptables rule was added successfully
if [ $? -eq 0 ]; then
    echo "iptables rule for queue number ${QUEUE_NUM} added successfully."
else
    echo "Failed to add iptables rule for queue number ${QUEUE_NUM}." 1>&2
    exit 1
fi

