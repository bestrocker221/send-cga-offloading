#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Illegal number of parameters"
    echo "usage: ./client_measure.sh <interface> <server_ip> <server_port>"
    exit 0
fi

IFACE=$1
SERVER_IP=$2
SERVER_PORT=$3

for i in `seq 1 150`; do
	sudo python sclient.py -i ${IFACE} -m 1 | awk '{print $6}' | head -n 1 >> measurements_local.txt
done

for i in `seq 1 150`; do
	sudo python sclient.py -i ${IFACE} -m 2 --ip ${SERVER_IP} --port ${SERVER_PORT} | awk '{print $7}' | head -n 1 >> measurements_offloaded.txt
done