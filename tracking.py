"""Rastreio simples de estado para eventos ARP, ICMP e TCP."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from parsing import format_tcp_flags


TcpKey = tuple[str, int, str, int]


@dataclass
class TrackerState:
    """Guarda o estado mínimo necessário para detetar eventos simples."""

    arp_requests: set[tuple[str, str]] = field(default_factory=set)
    icmp_echo_requests: set[tuple[str, str, Any, Any]] = field(default_factory=set)
    tcp_flows: dict[TcpKey, str] = field(default_factory=dict)


def process_packet_for_events(packet: Any, state: TrackerState) -> list[str]:
    """Processa um pacote e devolve eventos detetados, se existirem."""

    try:
        events: list[str] = []
        arp_event = process_arp_event(packet, state)
        icmp_event = process_icmp_event(packet, state)
        tcp_event = process_tcp_event(packet, state)

        if arp_event:
            events.append(arp_event)
        if icmp_event:
            events.append(icmp_event)
        if tcp_event:
            events.append(tcp_event)
        return events
    except Exception:
        return []


def process_arp_event(packet: Any, state: TrackerState) -> Optional[str]:
    """Deteta pares ARP request/reply de forma simples."""

    from scapy.layers.l2 import ARP

    if ARP not in packet:
        return None

    arp = packet[ARP]
    operation = getattr(arp, "op", None)
    src_ip = getattr(arp, "psrc", None)
    dst_ip = getattr(arp, "pdst", None)
    src_mac = getattr(arp, "hwsrc", None)

    if operation in (1, "who-has") and src_ip and dst_ip:
        state.arp_requests.add((src_ip, dst_ip))
        return None

    if operation in (2, "is-at") and src_ip and dst_ip:
        request_key = (dst_ip, src_ip)
        if request_key in state.arp_requests:
            state.arp_requests.discard(request_key)
            if src_mac:
                return f"[evento] ARP resolvido | {src_ip} está em {src_mac}"

    return None


def process_icmp_event(packet: Any, state: TrackerState) -> Optional[str]:
    """Deteta pares ICMP echo-request/echo-reply."""

    from scapy.layers.inet import ICMP, IP

    if IP not in packet or ICMP not in packet:
        return None

    ip = packet[IP]
    icmp = packet[ICMP]
    src_ip = getattr(ip, "src", None)
    dst_ip = getattr(ip, "dst", None)
    icmp_type = getattr(icmp, "type", None)
    icmp_code = getattr(icmp, "code", None)
    icmp_id = getattr(icmp, "id", None)
    icmp_seq = getattr(icmp, "seq", None)

    if icmp_type == 8 and icmp_code == 0 and src_ip and dst_ip:
        state.icmp_echo_requests.add((src_ip, dst_ip, icmp_id, icmp_seq))
        return None

    if icmp_type == 0 and icmp_code == 0 and src_ip and dst_ip:
        request_key = (dst_ip, src_ip, icmp_id, icmp_seq)
        if request_key in state.icmp_echo_requests:
            state.icmp_echo_requests.discard(request_key)
            return f"[evento] ICMP reply recebido | {src_ip} respondeu a {dst_ip}"

    return None


def process_tcp_event(packet: Any, state: TrackerState) -> Optional[str]:
    """Deteta handshakes TCP simples e encerramentos por FIN/RST."""

    from scapy.layers.inet import IP, TCP

    if IP not in packet or TCP not in packet:
        return None

    ip = packet[IP]
    tcp = packet[TCP]
    src_ip = getattr(ip, "src", None)
    dst_ip = getattr(ip, "dst", None)
    src_port = getattr(tcp, "sport", None)
    dst_port = getattr(tcp, "dport", None)

    if src_ip is None or dst_ip is None or src_port is None or dst_port is None:
        return None

    flags = format_tcp_flags(getattr(tcp, "flags", None)) or ""
    key = (src_ip, src_port, dst_ip, dst_port)
    reverse_key = (dst_ip, dst_port, src_ip, src_port)

    termination = detect_tcp_termination(flags)
    if termination:
        flow_key = key if key in state.tcp_flows else reverse_key
        if flow_key in state.tcp_flows:
            state.tcp_flows.pop(flow_key, None)
            return f"[evento] TCP sessão terminada | {format_tcp_key(flow_key)} | {termination}"
        return f"[evento] TCP sessão terminada | {format_tcp_key(key)} | {termination}"

    if flags == "SYN":
        state.tcp_flows.setdefault(key, "SYN")
        return None

    if flags == "SYN-ACK" and reverse_key in state.tcp_flows:
        if state.tcp_flows[reverse_key] == "SYN":
            state.tcp_flows[reverse_key] = "SYN-ACK"
        return None

    if flags == "ACK" and state.tcp_flows.get(key) == "SYN-ACK":
        state.tcp_flows[key] = "ESTABLISHED"
        return f"[evento] TCP handshake concluído | {format_tcp_key(key)}"

    return None


def detect_tcp_termination(flags: str) -> Optional[str]:
    """Identifica encerramento TCP por RST ou FIN."""

    if "RST" in flags:
        return "RST"
    if "FIN" in flags:
        return "FIN"
    return None


def format_tcp_key(key: TcpKey) -> str:
    """Formata a chave TCP orientada cliente -> servidor."""

    src_ip, src_port, dst_ip, dst_port = key
    return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
