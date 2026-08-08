#!/bin/bash
# Simple iptables Stealth NAT for Management Plane

# Enable IPv4 forwarding in the kernel
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "Applying NAT rules..."

# 1. DNAT: Redirect incoming Splunk forwarder traffic (9997) from the gateway IP to the real Splunk IP
iptables -t nat -A PREROUTING -i br-vs2 -d 10.254.2.1 -p tcp --dport 9997 -j DNAT --to-destination 10.254.2.100:9997

# 2. SNAT: Hide the SOC IP by rewriting outbound WinRM traffic (5985) to look like it came from the gateway
iptables -t nat -A POSTROUTING -o br-vs2 -s 10.254.2.100 -p tcp --dport 5985 -j SNAT --to-source 10.254.2.1

echo "NAT setup complete."
