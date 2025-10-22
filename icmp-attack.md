# What that attack is called (short)

- Primary name: **ICMP flood** (a form of volumetric/denial-of-service).
- With large payloads/fragmentation it’s often described as **ICMP fragmentation flood** or **ICMP flood with IP fragmentation**.
- Category: **Volumetric network-layer DDoS** (resource exhaustion at the network/IP level).

# What it does & how it works (conceptual)

- The attacker sends a *very large* stream of ICMP Echo Request (ping) packets as fast as possible.
- With `d 5000` the payload exceeds the typical MTU (~1500 bytes), so the IP layer fragments each packet into multiple IP fragments. This multiplies the per-packet work for the receiver (more packets to process + IP reassembly work).
- Effects:
    - **Bandwidth saturation**: saturates the link between sender and target so legitimate traffic is delayed/dropped.
    - **CPU / kernel workload**: the kernel must handle many packets, interrupts, and possibly reassemble fragments — raising CPU and memory use.
    - **Queue exhaustion**: NIC, kernel, or router queues fill and packets drop (including legitimate traffic).
    - **State exhaustion**: in some cases kernel tables (e.g., IP reassembly buffers, conntrack) or userland processes can be overwhelmed.
- Outcome: legitimate services slow or become unavailable; network may be congested or devices may fail open/slow.

# Which OSI layer is affected

- **Primary:** Layer **3 — Network layer** (ICMP and IP fragmentation are network-layer).
- **Secondary effects:** Layer **2 (link)** and **1 (physical)** because a saturated link/medium is an L1/L2 issue; Layer **4/7** services (TCP/HTTP) may also be impacted indirectly due to increased latency, packet loss or server resource exhaustion.

# How to detect this attack (signs / telemetry)

- Sudden spike in inbound ICMP rate (`tcpdump icmp` or packet counters).
- High number of small fragments or a rise in IP fragments (`tcpdump 'ip[6:2] & 0x1fff != 0'` or equivalent).
- NIC/host packets/s interrupts and RX queue growth.
- Increased CPU usage in softirq/interrupt context (`top`/`htop`, look at `si/hi` in vmstat).
- Large number of dropped packets in `ifconfig`/`ip -s link` or `netstat -s`.
- Kernel/log warnings about IP reassembly or memory.
- High `nf_conntrack` counts (if relevant) or socket exhaustion.
- IDS/NetFlow/sFlow/NetMon alerts about unusual ICMP volume or abnormal flows.

# Precautions — general principles

1. **Isolate and test in labs** (use internal networks, snapshots).
2. **Never** perform uncontrolled flooding on shared or public networks.
3. **Monitor baseline** traffic so anomalies show clearly.
4. **Apply filtering upstream** (at routers/CDN/ISP) whenever possible — stop bad traffic before it hits your host.
5. Balance **availability** vs **connectivity** — overzealous ICMP blocking can break diagnostics and some legitimate protocols (PMTU discovery).

# Practical mitigation methods (from host to network) — with examples

> These are defensive commands you can run on the machine you control. Test carefully, take snapshots, and consider production impact.
> 

## 1) Rate-limit or drop ICMP on the host (iptables example)

Allow small healthy ICMP while dropping bursts:

```bash
# Allow up to 2 pings per second with a small burst, then drop extras
sudo iptables -I INPUT -p icmp --icmp-type echo-request -m limit --limit 2/second --limit-burst 5 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

```

To remove:

```bash
sudo iptables -D INPUT -p icmp --icmp-type echo-request -m limit --limit 2/second --limit-burst 5 -j ACCEPT
sudo iptables -D INPUT -p icmp --icmp-type echo-request -j DROP

```

**Trade-off:** legitimate heavy diagnostic traffic will be dropped; tune limits to your environment.

## 2) Drop IP fragments early (iptables raw table)

If fragmentation reassembly is causing CPU/memory issues, drop fragments:

```bash
# Drop non-initial fragments
sudo iptables -t raw -A PREROUTING -f -j DROP

```

**Note:** some legitimate traffic uses fragmentation; use carefully — if you host services that legitimately require large packets, you may need a more nuanced policy.

## 3) nftables equivalent (modern Linux)

```bash
# Basic ICMP rate-limit with nftables
sudo nft add table inet filter
sudo nft 'add chain inet filter input { type filter hook input priority 0; }'
sudo nft add rule inet filter input icmp type echo-request limit rate 2/second burst 5 packets accept
sudo nft add rule inet filter input icmp type echo-request drop

```

## 4) Kernel tuning (reduce reassembly impact; be conservative)

You can reduce the memory used for IP fragmentation reassembly (values vary by kernel):

```bash
# show current thresholds
sysctl net.ipv4.ipfrag_high_thresh
sysctl net.ipv4.ipfrag_low_thresh

# lower them (example values — adjust carefully)
sudo sysctl -w net.ipv4.ipfrag_high_thresh=1048576    # bytes
sudo sysctl -w net.ipv4.ipfrag_low_thresh=786432

```

Or temporarily ignore ICMP echo:

```bash
# ignore all ICMP echo (pings) — blunt instrument
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
# reset to 0 to re-enable
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0

```

**Trade-off:** disabling ICMP prevents ping/traceroute and can break PMTU.

## 5) Rate limiting at the interface (tc) — shape/limit ingress

You can limit how much traffic the host will accept (ingress policing or TBF):

```bash
# Example: limit ingress to 10mbit on eth0 (requires care)
sudo tc qdisc add dev eth0 root tbf rate 10mbit burst 32kbit latency 400ms

```



# Example: limit ingress to 10mbit on eth0 (requires care)
sudo tc qdisc add dev eth0 root tbf rate 10mbit burst 32kbit latency 400ms





ATTACK STEPS:

1. Ping the attacking system .
2. In the attacking system check the icmp packets using " netstat -s | grep -i icmp "
3. In the host system use the command : " sudo hping3 -1 --flood -d 5000 ipaddress"
<img width="816" height="323" alt="Screenshot 2025-10-22 101541" src="https://github.com/user-attachments/assets/3b388201-74da-4b9b-9509-08c2c3f2a333" />

