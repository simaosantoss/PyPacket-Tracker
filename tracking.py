"""Rastreio simples de estado para eventos ARP, ICMP, TCP, traceroute e fragmentação."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from parsing import format_tcp_flags


TcpKey = tuple[str, int, str, int]
TracerouteKey = tuple[str, str, str]
FragmentKey = tuple[str, str, int, Any]
DnsKey = tuple[str, str, Any, Any, Any]


@dataclass
class TrackerState:
    """Guarda o estado mínimo necessário para detetar eventos simples."""

    arp_requests: dict[tuple[str, str], Optional[int]] = field(default_factory=dict)
    icmp_echo_requests: dict[tuple[str, str, Any, Any], Optional[int]] = field(
        default_factory=dict
    )
    dns_queries: dict[DnsKey, Optional[int]] = field(default_factory=dict)
    tcp_flows: dict[TcpKey, str] = field(default_factory=dict)
    traceroute_flows: dict[TracerouteKey, dict[str, Any]] = field(default_factory=dict)
    ipv4_fragments: dict[FragmentKey, dict[str, Any]] = field(default_factory=dict)


def process_packet_for_events(packet: Any, state: TrackerState) -> list[str]:
    """Processa um pacote e devolve eventos detetados, se existirem."""

    events, _ = process_packet_tracking(packet, state, packet_number=None)
    return events


def process_packet_tracking(
    packet: Any, state: TrackerState, packet_number: Optional[int]
) -> tuple[list[str], list[str]]:
    """Processa um pacote e devolve eventos e anotações para o resumo."""

    try:
        events: list[str] = []
        annotations: list[str] = []
        arp_event, arp_annotation = process_arp_tracking(packet, state, packet_number)
        icmp_event, icmp_annotation = process_icmp_tracking(
            packet, state, packet_number
        )
        dns_annotation = process_dns_tracking(packet, state, packet_number)
        tcp_event = process_tcp_event(packet, state)
        traceroute_event = process_traceroute_event(packet, state)
        fragment_event = process_ipv4_fragment_event(packet, state)

        if arp_event:
            events.append(arp_event)
        if arp_annotation:
            annotations.append(arp_annotation)
        if icmp_event:
            events.append(icmp_event)
        if icmp_annotation:
            annotations.append(icmp_annotation)
        if dns_annotation:
            annotations.append(dns_annotation)
        if tcp_event:
            events.append(tcp_event)
        if traceroute_event:
            events.append(traceroute_event)
        if fragment_event:
            events.append(fragment_event)
        return events, annotations
    except Exception:
        return [], []


def process_arp_tracking(
    packet: Any, state: TrackerState, packet_number: Optional[int]
) -> tuple[Optional[str], Optional[str]]:
    """Deteta pares ARP request/reply e referencia a linha do pedido."""

    from scapy.layers.l2 import ARP

    if ARP not in packet:
        return None, None

    arp = packet[ARP]
    operation = getattr(arp, "op", None)
    src_ip = getattr(arp, "psrc", None)
    dst_ip = getattr(arp, "pdst", None)
    src_mac = getattr(arp, "hwsrc", None)

    if operation in (1, "who-has") and src_ip and dst_ip:
        state.arp_requests[(src_ip, dst_ip)] = packet_number
        return None, None

    if operation in (2, "is-at") and src_ip and dst_ip:
        request_key = (dst_ip, src_ip)
        if request_key in state.arp_requests:
            request_line = state.arp_requests.pop(request_key)
            annotation = format_line_reference("request in line", request_line)
            if src_mac:
                return (
                    f"[evento] ARP resolvido | {src_ip} está em {src_mac}",
                    annotation,
                )
            return None, annotation

    return None, None


def process_icmp_tracking(
    packet: Any, state: TrackerState, packet_number: Optional[int]
) -> tuple[Optional[str], Optional[str]]:
    """Deteta pares ICMP echo-request/echo-reply e referencia a linha do pedido."""

    from scapy.layers.inet import ICMP, IP

    if IP not in packet or ICMP not in packet:
        return None, None

    ip = packet[IP]
    icmp = packet[ICMP]
    src_ip = getattr(ip, "src", None)
    dst_ip = getattr(ip, "dst", None)
    icmp_type = getattr(icmp, "type", None)
    icmp_code = getattr(icmp, "code", None)
    icmp_id = getattr(icmp, "id", None)
    icmp_seq = getattr(icmp, "seq", None)

    if icmp_type == 8 and icmp_code == 0 and src_ip and dst_ip:
        state.icmp_echo_requests[(src_ip, dst_ip, icmp_id, icmp_seq)] = packet_number
        return None, None

    if icmp_type == 0 and icmp_code == 0 and src_ip and dst_ip:
        request_key = (dst_ip, src_ip, icmp_id, icmp_seq)
        if request_key in state.icmp_echo_requests:
            request_line = state.icmp_echo_requests.pop(request_key)
            annotation = format_line_reference("request in line", request_line)
            return (
                f"[evento] ICMP reply recebido | {src_ip} respondeu a {dst_ip}",
                annotation,
            )

    return None, None


def process_dns_tracking(
    packet: Any, state: TrackerState, packet_number: Optional[int]
) -> Optional[str]:
    """Liga respostas DNS à linha da query observada."""

    try:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, UDP
    except ModuleNotFoundError:
        return None

    if IP not in packet or UDP not in packet or DNS not in packet:
        return None

    ip = packet[IP]
    udp = packet[UDP]
    dns = packet[DNS]
    src_ip = getattr(ip, "src", None)
    dst_ip = getattr(ip, "dst", None)
    src_port = getattr(udp, "sport", None)
    dst_port = getattr(udp, "dport", None)
    dns_id = getattr(dns, "id", None)
    query_response = getattr(dns, "qr", None)

    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        return None

    if len(state.dns_queries) > 512:
        state.dns_queries.clear()

    if query_response == 0:
        state.dns_queries[(src_ip, dst_ip, src_port, dst_port, dns_id)] = packet_number
        return None

    if query_response == 1:
        query_key = (dst_ip, src_ip, dst_port, src_port, dns_id)
        query_line = state.dns_queries.pop(query_key, None)
        return format_line_reference("request in line", query_line)

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


def process_traceroute_event(packet: Any, state: TrackerState) -> Optional[str]:
    """Deteta um padrão simples de traceroute com TTL crescente."""

    from scapy.layers.inet import IP

    if IP not in packet:
        return None

    ip = packet[IP]
    src_ip = getattr(ip, "src", None)
    dst_ip = getattr(ip, "dst", None)
    ttl = getattr(ip, "ttl", None)
    protocol = normalize_transport_protocol(getattr(ip, "proto", None))

    if not src_ip or not dst_ip or ttl is None or not protocol:
        return None

    key = (src_ip, dst_ip, protocol)
    ttl = int(ttl)

    # Mantém esta memória curta e focada no padrão típico de traceroute.
    if ttl < 1 or ttl > 32:
        state.traceroute_flows.pop(key, None)
        return None

    if len(state.traceroute_flows) > 256:
        state.traceroute_flows.clear()

    flow_state = state.traceroute_flows.get(
        key,
        {"last_ttl": ttl, "streak": 1, "detected": False},
    )
    last_ttl = flow_state["last_ttl"]
    streak = flow_state["streak"]
    detected = flow_state["detected"]

    if ttl == last_ttl:
        state.traceroute_flows[key] = flow_state
        return None

    if ttl == 1 or ttl < last_ttl or ttl > last_ttl + 2:
        state.traceroute_flows[key] = {
            "last_ttl": ttl,
            "streak": 1,
            "detected": False,
        }
        return None

    streak += 1
    flow_state["last_ttl"] = ttl
    flow_state["streak"] = streak

    if streak >= 4 and not detected:
        flow_state["detected"] = True
        state.traceroute_flows[key] = flow_state
        return f"[evento] Possível traceroute detetado | {src_ip} -> {dst_ip}"

    state.traceroute_flows[key] = flow_state
    return None


def process_ipv4_fragment_event(packet: Any, state: TrackerState) -> Optional[str]:
    """Agrupa fragmentos IPv4 e emite um evento quando o conjunto parece completo."""

    from scapy.layers.inet import IP

    if IP not in packet:
        return None

    ip = packet[IP]
    src_ip = getattr(ip, "src", None)
    dst_ip = getattr(ip, "dst", None)
    identification = getattr(ip, "id", None)
    protocol = getattr(ip, "proto", None)
    offset = get_fragment_offset_bytes(ip)
    more_fragments = has_more_fragments(ip)

    if (
        src_ip is None
        or dst_ip is None
        or identification is None
        or protocol is None
        or (offset == 0 and not more_fragments)
    ):
        return None

    payload_length = get_ipv4_payload_length(ip)
    if payload_length <= 0:
        return None

    if len(state.ipv4_fragments) > 256:
        state.ipv4_fragments.clear()

    key = (src_ip, dst_ip, int(identification), protocol)
    fragment_state = state.ipv4_fragments.setdefault(
        key,
        {
            "ranges": set(),
            "expected_total": None,
            "completed": False,
        },
    )
    fragment_state["ranges"].add((offset, offset + payload_length))

    if not more_fragments:
        fragment_state["expected_total"] = offset + payload_length

    if fragment_state["completed"] or fragment_state["expected_total"] is None:
        return None

    expected_total = fragment_state["expected_total"]
    if ranges_cover_total(fragment_state["ranges"], expected_total):
        fragment_state["completed"] = True
        return (
            f"[evento] Fragmentos IPv4 completos | {src_ip} -> {dst_ip} "
            f"| id={identification}"
        )

    return None


def detect_tcp_termination(flags: str) -> Optional[str]:
    """Identifica encerramento TCP por RST ou FIN."""

    if "RST" in flags:
        return "RST"
    if "FIN" in flags:
        return "FIN"
    return None


def format_line_reference(label: str, packet_number: Optional[int]) -> Optional[str]:
    """Formata uma referência curta para outra linha observada."""

    if packet_number is None:
        return None
    return f"{label} {packet_number}"


def normalize_transport_protocol(value: Any) -> Optional[str]:
    """Normaliza o protocolo IPv4 para uma etiqueta curta e estável."""

    mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return mapping.get(value)


def get_fragment_offset_bytes(ip: Any) -> int:
    """Converte o offset do cabeçalho IPv4 para bytes."""

    fragment_offset = getattr(ip, "frag", 0)
    try:
        return int(fragment_offset) * 8
    except (TypeError, ValueError):
        return 0


def has_more_fragments(ip: Any) -> bool:
    """Indica se a flag MF está ativa."""

    return "MF" in str(getattr(ip, "flags", ""))


def get_ipv4_payload_length(ip: Any) -> int:
    """Obtém o comprimento do payload IPv4 sem reconstrução profunda."""

    total_length = getattr(ip, "len", None)
    header_length = getattr(ip, "ihl", None)

    try:
        if total_length is not None and header_length is not None:
            return max(int(total_length) - int(header_length) * 4, 0)
    except (TypeError, ValueError):
        pass

    try:
        return len(bytes(ip.payload))
    except Exception:
        return 0


def ranges_cover_total(ranges: set[tuple[int, int]], expected_total: int) -> bool:
    """Verifica se os intervalos observados cobrem todo o datagrama esperado."""

    if not ranges or expected_total <= 0:
        return False

    ordered_ranges = sorted(ranges)
    coverage_end = 0

    for start, end in ordered_ranges:
        if start > coverage_end:
            return False
        coverage_end = max(coverage_end, end)
        if coverage_end >= expected_total:
            return True

    return False


def format_tcp_key(key: TcpKey) -> str:
    """Formata a chave TCP orientada cliente -> servidor."""

    src_ip, src_port, dst_ip, dst_port = key
    return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
