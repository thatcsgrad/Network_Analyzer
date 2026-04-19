# VPN Network Analyzer 🔍🛡️

A Python tool to measure and compare network behaviour **with and without a VPN**, exploring how Privacy-Enhancing Technologies affect performance, privacy, and DNS behaviour.

Built as a hands-on mini-project while learning network security fundamentals.

---

## What It Measures

| Metric | What It Tells Us |
|---|---|
| **Public IP & Location** | Whether the VPN successfully masks your real identity |
| **ICMP Ping Latency** | Performance overhead introduced by VPN tunnelling |
| **Jitter** | Stability of the connection under VPN |
| **Packet Loss** | Reliability impact |
| **DNS Resolution** | Whether DNS queries resolve differently under VPN |
| **DNS Leak Test** | Whether your real ISP is still visible via DNS queries |
| **HTTP Response Time** | End-to-end real-world speed impact |

---

## Why This Matters

VPNs are one of the most commonly deployed **Privacy-Enhancing Technologies (PETs)**. While they are designed to provide anonymity by masking IP addresses and encrypting traffic, their impact on real-world performance is often poorly understood.

This project is motivated by research questions like:
- Can VPNs maintain strong privacy guarantees without significantly degrading performance?
- Do DNS leaks undermine VPN privacy even when traffic is encrypted?
- How does routing through a VPN server affect latency for bandwidth-sensitive applications?

---

## Setup

### Requirements

- Python 3.8+
- `requests` library

```bash
pip install requests
```

### Run

```bash
python network_analyzer_miniproject.py
```

The tool will run through two phases:
1. **Phase 1** — run with VPN OFF (baseline measurement)
2. **Phase 2** — turn VPN ON, then run again

It will then print a side-by-side comparison and save full results to `results.json`.

---

## Sample Output

```
═══════════════════════════════════════════════════════════
   VPN Network Analyser — Privacy & Performance Tool
   Author: Sanika Rane
═══════════════════════════════════════════════════════════

[Press Enter to start — make sure VPN is OFF]

── Running analysis: WITHOUT VPN ──────────────────────────

[1] Checking public IP address...
    IP      : 103.x.x.x
    Location: Mumbai, IN
    ISP/Org : AS12345 Jio

[2] Measuring latency via ICMP ping...
    google.com             avg=12.4ms  jitter=2.1ms  loss=0.0%
    cloudflare.com         avg=14.8ms  jitter=3.2ms  loss=0.0%

...

── COMPARISON: Without VPN  vs  With VPN ──────────────────

Metric                       Without VPN                  With VPN
───────────────────────────────────────────────────────────────────────────
Public IP                    103.x.x.x                    185.y.y.y
Location                     Mumbai, IN                   Frankfurt, DE
ISP/Org                      Jio                          NordVPN

  Ping avg google.com        12.4   ms          89.2   ms   (+76.8 ms overhead)
  Ping avg cloudflare.com    14.8   ms          92.1   ms   (+77.3 ms overhead)

  HTTP latency (google.com)  180.0      ms      610.0      ms  (+430.0 ms)

  DNS leak detected?         No                           No

  Key Observations:
  ✓ VPN successfully masks your real IP address.
  ✓ Average VPN latency overhead: 77.1 ms across 3 hosts.
  ✓ No DNS leak detected with VPN active.
```

---

## Key Findings (Example)

- VPN adds significant latency overhead (~77ms in testing) due to encryption and traffic rerouting
- IP masking works correctly - public IP changes to VPN server location
- DNS queries are routed through VPN, preventing ISP-level DNS leaks
- For latency-sensitive applications (video calls, gaming), this overhead could impact usability

---

## Concepts Covered

- **VPN tunnelling** and how it routes traffic
- **DNS leak detection** — a common VPN privacy weakness
- **ICMP (ping)** for measuring network round-trip time
- **Jitter** — variation in latency, important for real-time applications
- **Privacy-Enhancing Technologies (PETs)** — tools designed to reduce identifiable network footprint

---

## Relevance to Research

This project was built as an introduction to the measurement methodologies used in network privacy research, specifically:

- **Active measurement tools** for evaluating VPN performance
- **Traffic analysis** to understand what information leaks through PETs
- Understanding trade-offs between **privacy** and **performance** in VPN deployments

It relates directly to research on:
- Performance Evaluation of Privacy-Enhancing Networks
- Next-Generation VPN Architectures
- Discovery of Privacy-Enhancing Infrastructure

---

## Future Improvements

- [ ] Integrate Scapy for packet-level traffic capture and analysis
- [ ] Add Wireshark `.pcap` export for deeper analysis
- [ ] Test across multiple VPN protocols (OpenVPN vs WireGuard vs SSTP)

---

## Author

**Sanika Rane**
B.E. Computer Engineering | Cybersecurity Enthusiast
[LinkedIn](https://www.linkedin.com/in/thatcsgrad/)
