# Packet Sniffer and Traffic Analyzer

![Status](https://img.shields.io/badge/status-completed-brightgreen)
![Language](https://img.shields.io/badge/language-Python-blue)
![Library](https://img.shields.io/badge/library-Scapy-orange)

---

## About

This project is a packet sniffer and traffic analyzer developed for the Computer Networks course, a 2nd-year, 2nd-semester course in the Software Engineering degree at the University of Minho, academic year 2025/2026.

The assignment goal was to build a sniffer capable of capturing network packets, identifying relevant protocols, applying filters, logging captures, and relating observed packets to the typical interactions of each protocol. The project was tested both in an emulated CORE network and on a real computer network interface.

The original project statement is available in [`statement.pdf`](./statement.pdf). It is written in Portuguese, as it was the official assignment statement for the course.

The full usage guide is available in [`USAGE.md`](./USAGE.md). It is written in Portuguese because this was an academic project developed and demonstrated in Portuguese.

## Main Features

- Live packet capture from a selected network interface.
- Offline analysis of `.pcap` files.
- Raw capture export to `.pcap`.
- Console output with one readable summary per packet.
- Structured logging in `txt`, `csv`, and JSON Lines.
- Interactive packet detail view after a capture.
- Final traffic statistics with protocol counts, top source IPs, and detected events.
- Friendly CLI filters for IP, MAC, protocol, ports, and IPv4 fragmentation.
- BPF capture filters in live mode.
- Conservative service identification for DNS, DHCP, and HTTP.
- Stateful event tracking across related packets.

## Supported Protocol Analysis

The sniffer parses and summarizes:

| Layer / Protocol | Information shown |
|------------------|-------------------|
| Ethernet | Source MAC, destination MAC, EtherType |
| ARP | Request/reply operation, IP/MAC mapping, matched replies |
| IPv4 | Source/destination IP, TTL, total length, protocol, fragmentation fields |
| ICMP | Type, code, echo request/reply, matched replies |
| TCP | Source/destination ports, flags, HTTP by port 80, handshake and termination events |
| UDP | Source/destination ports, DNS/DHCP services when identifiable |
| DNS | Query/response recognition when decoded by Scapy |
| DHCP | Discover, Offer, Request, and ACK recognition when decoded by Scapy |

The project also includes simple tracking for:

- ARP request/reply pairs.
- ICMP echo request/reply pairs.
- DNS query/response pairs.
- TCP three-way handshakes.
- TCP session termination through `FIN` or `RST`.
- Possible traceroute patterns through increasing TTL values.
- IPv4 fragment groups and heuristic detection of complete fragment sets.

## Project Structure

```text
main.py            CLI, argument validation, filters, and final summary
capture.py         Live/offline capture execution and packet processing
parsing.py         Protocol parsing, friendly filters, packet summaries, details
tracking.py        Stateful tracking of protocol interactions and events
logging_output.py  Structured output in txt, csv, and JSON Lines
stats.py           Final traffic statistics
USAGE.md           Complete usage and validation guide in Portuguese
```

## Requirements

- Python 3
- [Scapy](https://scapy.net/)
- Administrator/root permissions for live captures on real interfaces

A virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install scapy
```

The CLI help can be displayed with:

```bash
python3 main.py --help
```

## Quick Start

Run a short live capture on macOS:

```bash
sudo .venv/bin/python main.py -i en0 -c 10
```

Run a short live capture on Linux or CORE:

```bash
sudo python3 main.py -i eth0 -c 10
```

Capture packets and save the raw traffic to a PCAP file:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

Read packets from a PCAP file:

```bash
python3 main.py -r captura.pcap -c 10
```

Generate a structured CSV log while reading a PCAP:

```bash
python3 main.py -r captura.pcap --log-file captura.csv --log-format csv
```

## CLI Filters

The program supports friendly filters that can be used in both live and offline mode:

```bash
python3 main.py -r captura.pcap --protocol tcp
python3 main.py -r captura.pcap --ip 10.0.0.1
python3 main.py -r captura.pcap --src-ip 10.0.0.1
python3 main.py -r captura.pcap --dst-ip 8.8.8.8
python3 main.py -r captura.pcap --mac aa:bb:cc:dd:ee:ff
python3 main.py -r captura.pcap --src-port 53000
python3 main.py -r captura.pcap --dst-port 53 --protocol udp
python3 main.py -r fragmentado.pcap --fragmented
python3 main.py -r fragmentado.pcap --ip-id 12345
python3 main.py -r fragmentado.pcap --mf-only
```

In live mode, BPF expressions can also be used:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "udp port 53"
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
sudo .venv/bin/python main.py -i en0 --bpf "host 8.8.8.8"
```

BPF is intentionally only supported for live captures. Offline `.pcap` analysis uses the friendly CLI filters above.

## Example Output

```text
[12] [live:en0] [14:02:10] Ethernet | IPv4 | UDP | 10.0.0.1:53000 -> 8.8.8.8:53 | ttl=64 | DNS query | 72 bytes
[13] [live:en0] [14:02:11] Ethernet | IPv4 | UDP | 8.8.8.8:53 -> 10.0.0.1:53000 | ttl=64 | DNS response | 72 bytes | request in line 12
[evento] ICMP reply recebido | 8.8.8.8 respondeu a 10.0.0.1
```

At the end of the execution, the sniffer prints a summary with the source used, configured filters, number of processed packets, protocol distribution, top talkers, and event counters.

## Validation and Testing

The project was validated through command-line tests, CORE experiments, offline PCAP analysis, and live captures on a real network interface.

Validation included:

- Checking CLI help and invalid argument handling.
- Capturing live traffic with packet count and timeout limits.
- Reading previously generated `.pcap` files.
- Exporting raw captures with `--write-pcap`.
- Generating logs in `txt`, `csv`, and JSON Lines.
- Filtering by protocol, IP, MAC, ports, and IPv4 fragmentation fields.
- Testing BPF filters in live mode.
- Triggering ICMP traffic with `ping`.
- Triggering DNS traffic with `dig` or `nslookup`.
- Triggering TCP/HTTP traffic with `curl`.
- Observing ARP in a local/CORE network.
- Observing TCP handshakes and connection termination.
- Testing traceroute detection with increasing TTL traffic.
- Testing IPv4 fragmentation with prepared fragmented traffic.

More detailed validation commands and expected results are documented in [`USAGE.md`](./USAGE.md).

## CORE and Real Interface Usage

For the CORE part of the assignment, the sniffer was executed inside the emulated network and used to observe controlled traffic such as ARP, ICMP, TCP/HTTP, DNS/UDP, traceroute-style traffic, and IPv4 fragmentation scenarios.

For the real interface part, the sniffer was executed on the computer network interface, such as `en0` on macOS or `eth0`/`wlan0` on Linux. Live capture requires administrator/root permissions.

The tool is intended for passive inspection only. It should only be used on authorized networks, such as the CORE topology or my own network. It does not implement packet injection, MITM, deauthentication, or sensitive data collection features.

## AI-Assisted Development

AI tools were used during development as a programming aid, in accordance with the rules communicated by the course instructors. I guided and reviewed their use: prompts, design decisions, implementation direction, validation, and final responsibility remained under my control.

In practice, AI was used as a support tool to work more effectively, not as a replacement for understanding the problem, defining the solution, or blindly generating the project.

## Authors

- [Simão Santos](https://github.com/simaosantoss)
