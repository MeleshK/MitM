#!/bin/bash

#terminate mitmdump if already running.
try:
  kill "$(pgrep mitmdump)"

export SSLKEYLOGFILE=/project/keylogfile.txt

now=$(date +"%Y_%m_%d_%H_%M")

#Starts mitmdump and outputs to output.txt
# sudo tcpdump -w "Capture/mitmproxy_$now.pcap" -B 40960 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0' -i wlan0 &

mitmdump --anticomp --anticache --set block_global=false --set flow_detail=3 --mode transparent --showhost --save-stream-file "Capture/mitmproxy_$now.cap" --set stream_large_bodies=5m --ssl-insecure --verbose &
