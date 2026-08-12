# Network Plumbing: Linux `tc` Packet Mirroring & Stealth NAT

## 1. Linux Traffic Control (`tc`) Packet Cloning Engine

In enterprise environments, network monitoring tools rely on physical **Test Access Points (TAPs)** or managed switch **Switched Port Analyzer (SPAN)** mirror ports. In this virtualized environment, this functionality is replicated using the Linux kernel's native Traffic Control subsystem (`tc`) and the `mirred` action.

### The Unidirectional Egress Mirroring Rationale
A common pitfall in software switch mirroring is packet duplication. When a frame traverses from `tap-win1` to `tap-ad1` across a bridge:
* If both ingress and egress are mirrored on all ports, the frame is copied upon entering `tap-win1` and copied again upon leaving `tap-ad1`.
* In Zeek and Suricata, this produces double session counts, distorted byte calculations, and corrupted TCP state machines.

To resolve this, Alpine implements strict **unidirectional egress mirroring**:
```bash
# Attach clsact qdisc to switch port
tc qdisc add dev tap-win1 clsact

# Mirror ONLY egress frames to the promiscuous sniffing interface
tc filter add dev tap-win1 egress matchall \
    action mirred egress mirror dev veth-promisc
```
By capturing only at egress across each monitored port, every network transaction traversing V.S 1 is copied to `veth-promisc` **exactly once**.

---

## 2. Stealth NAT Engine (`iptables` DNAT & SNAT)

The management plane (**V.S 2**) connects the victim machines directly to the SOC infrastructure. To prevent an active adversary who gains code execution on `HR-01` or `AD / Server` from discovering the real IP address of the SOC machine, Alpine deploys a dual NAT architecture.

```mermaid
flowchart LR
    subgraph Victim VMs
        WIN[HR-01 / WIN.VM]
        AD[AD Domain Controller]
    end

    subgraph Virtual Switch 2 (Management Plane)
        GW["Gateway VIP (10.254.2.1)"]
    end

    subgraph SOC Infrastructure (Arch Host)
        SPLUNK["Splunk Indexer (10.254.2.100:9997)"]
        SOAR["Flask Micro-SOAR (10.254.2.100:5000)"]
    end

    WIN -- "Log Shipping (9997)" --> GW
    GW -- "DNAT Rewrite" --> SPLUNK
    SOAR -- "WinRM Containment (5985)" --> GW
    GW -- "SNAT Masquerade" --> WIN
```

### Inbound Log Shipping: Destination NAT (DNAT)
* **Problem**: If endpoints configure their Splunk Universal Forwarder `outputs.conf` to the real SOC IP (`10.254.2.100`), an adversary running `netstat -ano` or reading `outputs.conf` immediately maps the SOC machine.
* **Solution**: The forwarders are configured to send data to the gateway VIP (`10.254.2.1:9997`).
* **iptables Rule**:
  ```bash
  iptables -t nat -A PREROUTING -i br-vs2 -d 10.254.2.1 -p tcp --dport 9997 \
      -j DNAT --to-destination 10.254.2.100:9997
  ```
  The endpoint communicates with `10.254.2.1`, leaving the real Splunk instance completely obscured.

### Outbound Incident Response: Source NAT (SNAT)
* **Problem**: When the Python Micro-SOAR triggers PowerShell host quarantine via WinRM (TCP 5985), an adversary monitoring incoming packets would see connections originating from `10.254.2.100`.
* **Solution**: The outbound WinRM packets have their source address rewritten to the gateway VIP (`10.254.2.1`).
* **iptables Rule**:
  ```bash
  iptables -t nat -A POSTROUTING -o br-vs2 -s 10.254.2.100 -p tcp --dport 5985 \
      -j SNAT --to-source 10.254.2.1
  ```
  Windows Event Logs (Security Event ID 4624) and Defender Firewall connection tables show the connection originated from the network gateway router, eliminating SOC footprint leakage.
