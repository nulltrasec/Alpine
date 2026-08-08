#!/bin/bash
# Simple tc (Traffic Control) Packet Mirroring Script

SNIFF_IFACE="veth-promisc"

# Bring up the sniffing interface in promiscuous mode
ip link set dev $SNIFF_IFACE promisc on
ip link set dev $SNIFF_IFACE up

echo "Setting up egress mirroring using tc..."

# Mirror the AD Domain Controller VM
tc qdisc add dev tap-ad1 clsact
tc filter add dev tap-ad1 egress matchall action mirred egress mirror dev $SNIFF_IFACE

# Mirror the Windows Victim VM
tc qdisc add dev tap-win1 clsact
tc filter add dev tap-win1 egress matchall action mirred egress mirror dev $SNIFF_IFACE

# Mirror the Attacker VM
tc qdisc add dev tap-att1 clsact
tc filter add dev tap-att1 egress matchall action mirred egress mirror dev $SNIFF_IFACE

echo "Packet cloning is active."
