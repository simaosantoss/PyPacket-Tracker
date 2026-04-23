"""Parsing e resumo textual dos pacotes suportados pelo sniffer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


IP_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "ACK": 0x10}
ETHERTYPE_NAMES = {0x0800: "IPv4", 0x0806: "ARP"}


@dataclass(frozen=True)
class FriendlyFilters:
    """Agrupa os filtros simples que podem ser avaliados diretamente em Python."""

    ip: Optional[str] = None
    mac: Optional[str] = None
    protocol: Optional[str] = None


def packet_matches_friendly_filters(
    packet: Any, friendly_filters: FriendlyFilters
) -> bool:
    """Verifica se um pacote respeita os filtros simples configurados."""

    if friendly_filters.ip and not packet_matches_ip(packet, friendly_filters.ip):
        return False

    if friendly_filters.mac and not packet_matches_mac(packet, friendly_filters.mac):
        return False

    if friendly_filters.protocol and not packet_matches_protocol(
        packet, friendly_filters.protocol
    ):
        return False

    return True


def packet_matches_ip(packet: Any, ip_address: str) -> bool:
    """Verifica se o pacote tem o IP indicado como origem ou destino."""

    from scapy.layers.inet import IP

    return IP in packet and (
        packet[IP].src == ip_address or packet[IP].dst == ip_address
    )


def packet_matches_mac(packet: Any, mac_address: str) -> bool:
    """Verifica se o pacote tem o MAC indicado como origem ou destino Ethernet."""

    from scapy.layers.l2 import Ether

    wanted = mac_address.lower()
    return Ether in packet and (
        packet[Ether].src.lower() == wanted or packet[Ether].dst.lower() == wanted
    )


def packet_matches_protocol(packet: Any, protocol: str) -> bool:
    """Verifica se o pacote contém a camada do protocolo pedido."""

    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP

    protocol_layers = {
        "arp": ARP,
        "ip": IP,
        "icmp": ICMP,
        "tcp": TCP,
        "udp": UDP,
    }
    return protocol_layers[protocol] in packet


def extract_packet_info(packet: Any) -> dict[str, Any]:
    """Extrai os dados suportados nesta fase para um dicionário simples."""

    info: dict[str, Any] = {}
    ethernet_info = extract_ethernet_info(packet)
    arp_info = extract_arp_info(packet)
    ipv4_info = extract_ipv4_info(packet)

    if ethernet_info:
        info["ethernet"] = ethernet_info
    if arp_info:
        info["arp"] = arp_info
    if ipv4_info:
        info["ipv4"] = ipv4_info

    return info


def format_packet_timestamp(packet: Any) -> tuple[str, str]:
    """Formata o timestamp do pacote de forma robusta.

    O valor em ISO é usado nos logs estruturados. A hora curta mantém a linha
    da consola e do TXT legível.
    """

    raw_timestamp = getattr(packet, "time", None)

    try:
        timestamp = datetime.fromtimestamp(float(raw_timestamp))
    except (TypeError, ValueError, OverflowError, OSError):
        timestamp = datetime.now()

    return (
        timestamp.strftime("%H:%M:%S"),
        timestamp.isoformat(timespec="seconds"),
    )


def extract_ethernet_info(packet: Any) -> dict[str, Any]:
    """Extrai MACs e EtherType quando a camada Ethernet está presente."""

    from scapy.layers.l2 import Ether

    if Ether not in packet:
        return {}

    ethernet = packet[Ether]
    return {
        "src_mac": getattr(ethernet, "src", None),
        "dst_mac": getattr(ethernet, "dst", None),
        "ethertype": format_ethertype(getattr(ethernet, "type", None)),
    }


def extract_arp_info(packet: Any) -> dict[str, Any]:
    """Extrai a informação essencial de um pacote ARP."""

    from scapy.layers.l2 import ARP

    if ARP not in packet:
        return {}

    arp = packet[ARP]
    return {
        "operation": format_arp_operation(getattr(arp, "op", None)),
        "src_ip": getattr(arp, "psrc", None),
        "dst_ip": getattr(arp, "pdst", None),
        "src_mac": getattr(arp, "hwsrc", None),
        "dst_mac": getattr(arp, "hwdst", None),
    }


def extract_ipv4_info(packet: Any) -> dict[str, Any]:
    """Extrai a informação IPv4 e um resumo simples da camada de transporte."""

    from scapy.layers.inet import IP

    if IP not in packet:
        return {}

    ipv4 = packet[IP]
    proto = getattr(ipv4, "proto", None)
    protocol = IP_PROTOCOL_NAMES.get(proto, str(proto) if proto is not None else None)
    transport_info = extract_transport_info(packet, protocol)
    identification = getattr(ipv4, "id", None)
    fragment_offset = get_fragment_offset_bytes(ipv4)
    more_fragments = has_more_fragments(ipv4)
    is_fragmented = fragment_offset > 0 or more_fragments

    return {
        "src_ip": getattr(ipv4, "src", None),
        "dst_ip": getattr(ipv4, "dst", None),
        "ttl": getattr(ipv4, "ttl", None),
        "length": getattr(ipv4, "len", None),
        "protocol": protocol,
        "ip_id": identification,
        "fragment_offset": fragment_offset,
        "more_fragments": more_fragments,
        "is_fragmented": is_fragmented,
        "transport": transport_info,
    }


def extract_transport_info(packet: Any, protocol: Optional[str]) -> dict[str, Any]:
    """Escolhe o extractor L4 adequado, mantendo o parsing limitado."""

    if protocol == "ICMP":
        return extract_icmp_info(packet)
    if protocol == "TCP":
        return extract_tcp_info(packet)
    if protocol == "UDP":
        return extract_udp_info(packet)
    return {}


def extract_icmp_info(packet: Any) -> dict[str, Any]:
    """Extrai tipo e código ICMP, sem interpretar payload."""

    from scapy.layers.inet import ICMP

    if ICMP not in packet:
        return {}

    icmp = packet[ICMP]
    icmp_type = getattr(icmp, "type", None)
    icmp_code = getattr(icmp, "code", None)
    return {
        "protocol": "ICMP",
        "type": icmp_type,
        "code": icmp_code,
        "name": format_icmp_name(icmp_type, icmp_code),
    }


def extract_tcp_info(packet: Any) -> dict[str, Any]:
    """Extrai portas e flags TCP relevantes."""

    from scapy.layers.inet import TCP

    if TCP not in packet:
        return {}

    tcp = packet[TCP]
    src_port = getattr(tcp, "sport", None)
    dst_port = getattr(tcp, "dport", None)
    return {
        "protocol": "TCP",
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": format_tcp_flags(getattr(tcp, "flags", None)),
        "service": guess_service("TCP", src_port, dst_port),
    }


def extract_udp_info(packet: Any) -> dict[str, Any]:
    """Extrai portas UDP, sem analisar payload."""

    from scapy.layers.inet import UDP

    if UDP not in packet:
        return {}

    udp = packet[UDP]
    src_port = getattr(udp, "sport", None)
    dst_port = getattr(udp, "dport", None)
    return {
        "protocol": "UDP",
        "src_port": src_port,
        "dst_port": dst_port,
        "service": guess_service("UDP", src_port, dst_port),
        "detail": guess_udp_detail(packet),
    }


def format_ethertype(value: Any) -> Optional[str]:
    """Formata o EtherType de forma curta e reconhecível."""

    if value is None:
        return None
    if isinstance(value, int):
        name = ETHERTYPE_NAMES.get(value)
        return f"{name} (0x{value:04x})" if name else f"0x{value:04x}"
    return str(value)


def format_arp_operation(value: Any) -> Optional[str]:
    """Traduz operações ARP comuns para nomes simples."""

    operations = {
        1: "request",
        2: "reply",
        "who-has": "request",
        "is-at": "reply",
    }
    if value is None:
        return None
    return operations.get(value, str(value))


def format_icmp_name(icmp_type: Any, icmp_code: Any) -> Optional[str]:
    """Dá nomes curtos apenas a tipos ICMP comuns nesta fase."""

    if icmp_type == 8 and icmp_code == 0:
        return "echo-request"
    if icmp_type == 0 and icmp_code == 0:
        return "echo-reply"
    return None


def get_fragment_offset_bytes(ipv4: Any) -> int:
    """Converte o offset IPv4 para bytes."""

    fragment_offset = getattr(ipv4, "frag", 0)
    try:
        return int(fragment_offset) * 8
    except (TypeError, ValueError):
        return 0


def has_more_fragments(ipv4: Any) -> bool:
    """Indica se a flag MF está ativa."""

    flags = getattr(ipv4, "flags", "")
    return "MF" in str(flags)


def format_tcp_flags(flags: Any) -> Optional[str]:
    """Formata flags TCP comuns de forma curta."""

    if flags is None:
        return None

    labels: list[str] = []
    try:
        raw_flags = int(flags)
        for label, bit in TCP_FLAG_BITS.items():
            if raw_flags & bit:
                labels.append(label)
    except (TypeError, ValueError):
        raw_flags_text = str(flags)
        scapy_flags = {"F": "FIN", "S": "SYN", "R": "RST", "A": "ACK"}
        labels.extend(
            label for short, label in scapy_flags.items() if short in raw_flags_text
        )

    return "-".join(labels) if labels else str(flags)


def guess_service(protocol: str, src_port: Any, dst_port: Any) -> Optional[str]:
    """Sugere um serviço apenas quando a porta é suficientemente conhecida."""

    ports = {port for port in (src_port, dst_port) if isinstance(port, int)}

    if 53 in ports:
        return "DNS"
    if protocol == "UDP" and ports.intersection({67, 68}):
        return "DHCP"
    if protocol == "TCP" and 80 in ports:
        return "HTTP"
    return None


def guess_udp_detail(packet: Any) -> Optional[str]:
    """Reconhece apenas alguns casos UDP bem definidos."""

    dns_detail = guess_dns_detail(packet)
    if dns_detail:
        return dns_detail

    return guess_dhcp_detail(packet)


def guess_dns_detail(packet: Any) -> Optional[str]:
    """Distingue pedidos e respostas DNS quando a camada existe."""

    try:
        from scapy.layers.dns import DNS
    except ModuleNotFoundError:
        return None

    if DNS not in packet:
        return None

    dns = packet[DNS]
    qr = getattr(dns, "qr", None)
    if qr == 0:
        return "DNS query"
    if qr == 1:
        return "DNS response"
    return "DNS"


def guess_dhcp_detail(packet: Any) -> Optional[str]:
    """Reconhece alguns tipos DHCP a partir das opções do pacote."""

    try:
        from scapy.layers.dhcp import DHCP
    except ModuleNotFoundError:
        return None

    if DHCP not in packet:
        return None

    message_types = {
        1: "DHCP Discover",
        2: "DHCP Offer",
        3: "DHCP Request",
        5: "DHCP ACK",
        "discover": "DHCP Discover",
        "offer": "DHCP Offer",
        "request": "DHCP Request",
        "ack": "DHCP ACK",
    }

    options = getattr(packet[DHCP], "options", [])
    for option in options:
        if not (isinstance(option, tuple) and len(option) >= 2):
            continue
        if option[0] != "message-type":
            continue

        value = option[1]
        if isinstance(value, str):
            return message_types.get(value.lower())
        return message_types.get(value)

    return None


def format_direction(
    src: Any, dst: Any, src_label: str, dst_label: str
) -> Optional[str]:
    """Formata origem e destino sem inventar valores em falta."""

    if src and dst:
        return f"{src} -> {dst}"
    if src:
        return f"{src_label}={src}"
    if dst:
        return f"{dst_label}={dst}"
    return None


def format_endpoint(address: Any, port: Any, port_label: str) -> Optional[str]:
    """Formata um endpoint IP, com porta quando ela existe."""

    if address and port is not None:
        return f"{address}:{port}"
    if address:
        return str(address)
    if port is not None:
        return f"{port_label}={port}"
    return None


def format_ipv4_flow(info: dict[str, Any]) -> Optional[str]:
    """Formata origem e destino IPv4, incluindo portas TCP/UDP se existirem."""

    transport = info.get("transport", {})
    src = format_endpoint(info.get("src_ip"), transport.get("src_port"), "port_src")
    dst = format_endpoint(info.get("dst_ip"), transport.get("dst_port"), "port_dst")

    if src and dst:
        return f"{src} -> {dst}"
    if src:
        return src
    if dst:
        return dst
    return None


def summarize_packet(packet: Any, annotations: Optional[list[str]] = None) -> str:
    """Cria uma linha curta com o resumo suportado do pacote."""

    try:
        info = extract_packet_info(packet)
    except Exception:
        return append_summary_annotations(
            "Outro | pacote incompleto ou não suportado nesta fase", annotations
        )

    if "arp" in info:
        summary = add_link_layer_prefix(info, summarize_arp(info["arp"]))
        return append_summary_annotations(summary, annotations)
    if "ipv4" in info:
        summary = add_link_layer_prefix(info, summarize_ipv4(info["ipv4"]))
        return append_summary_annotations(summary, annotations)

    ethernet_info = info.get("ethernet", {})
    ethertype = ethernet_info.get("ethertype")
    if ethertype:
        summary = f"Ethernet | Outro | ethertype={ethertype} | tipo não suportado nesta fase"
        return append_summary_annotations(summary, annotations)
    return append_summary_annotations("Outro | tipo não suportado nesta fase", annotations)


def add_link_layer_prefix(info: dict[str, Any], summary: str) -> str:
    """Acrescenta Ethernet ao início do resumo quando a camada existe."""

    if "ethernet" in info:
        return f"Ethernet | {summary}"
    return summary


def append_summary_annotations(
    summary: str, annotations: Optional[list[str]]
) -> str:
    """Acrescenta referências entre pacotes no fim do resumo."""

    if not annotations:
        return summary
    return " | ".join([summary, *annotations])


def build_log_record(
    packet: Any,
    source_type: str,
    source_name: str,
    packet_number: int,
    summary: str,
) -> dict[str, Any]:
    """Constrói um registo achatado e estável para logging estruturado."""

    record: dict[str, Any] = {
        "packet_number": packet_number,
        "timestamp": "",
        "timestamp_display": "",
        "source_type": source_type,
        "source_name": source_name,
        "source_display": format_source_display(source_type, source_name),
        "summary": summary,
        "protocol": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": "",
        "dst_port": "",
        "ttl": "",
        "length": "",
        "ip_id": "",
        "fragment_offset": "",
        "more_fragments": "",
        "service": "",
    }

    timestamp_display, timestamp_iso = format_packet_timestamp(packet)
    record["timestamp"] = timestamp_iso
    record["timestamp_display"] = timestamp_display

    try:
        info = extract_packet_info(packet)
    except Exception:
        return record

    if "arp" in info:
        fill_arp_log_record(record, info["arp"])
    elif "ipv4" in info:
        fill_ipv4_log_record(record, info["ipv4"])

    return record


def format_source_display(source_type: str, source_name: str) -> str:
    """Formata a fonte tal como aparece no prefixo da consola."""

    source = source_name if source_type == "live" else Path(source_name).name
    return f"{source_type}:{source}"


def fill_arp_log_record(record: dict[str, Any], info: dict[str, Any]) -> None:
    """Preenche campos de log para ARP."""

    record["protocol"] = "ARP"
    record["src_ip"] = info.get("src_ip") or ""
    record["dst_ip"] = info.get("dst_ip") or ""


def fill_ipv4_log_record(record: dict[str, Any], info: dict[str, Any]) -> None:
    """Preenche campos de log para IPv4 e transporte, quando existir."""

    transport = info.get("transport", {})
    record["protocol"] = transport.get("protocol") or info.get("protocol") or "IPv4"
    record["src_ip"] = info.get("src_ip") or ""
    record["dst_ip"] = info.get("dst_ip") or ""
    record["ttl"] = info.get("ttl") if info.get("ttl") is not None else ""
    record["length"] = info.get("length") if info.get("length") is not None else ""
    record["ip_id"] = info.get("ip_id") if info.get("ip_id") is not None else ""
    record["fragment_offset"] = (
        info.get("fragment_offset") if info.get("fragment_offset") is not None else ""
    )
    record["more_fragments"] = (
        info.get("more_fragments") if info.get("more_fragments") is not None else ""
    )
    record["src_port"] = (
        transport.get("src_port") if transport.get("src_port") is not None else ""
    )
    record["dst_port"] = (
        transport.get("dst_port") if transport.get("dst_port") is not None else ""
    )
    record["service"] = transport.get("service") or ""


def summarize_arp(info: dict[str, Any]) -> str:
    """Cria um resumo textual curto para ARP."""

    parts = ["ARP"]
    if info.get("operation"):
        parts.append(info["operation"])

    ip_flow = format_direction(
        info.get("src_ip"), info.get("dst_ip"), "ip_src", "ip_dst"
    )
    if ip_flow:
        parts.append(ip_flow)

    mac_flow = format_direction(
        info.get("src_mac"), info.get("dst_mac"), "mac_src", "mac_dst"
    )
    if mac_flow:
        parts.append(mac_flow)

    return " | ".join(parts)


def summarize_ipv4(info: dict[str, Any]) -> str:
    """Cria um resumo textual curto para IPv4."""

    parts = ["IPv4"]
    ip_flow = format_ipv4_flow(info)
    if ip_flow:
        parts.append(ip_flow)
    if info.get("ttl") is not None:
        parts.append(f"ttl={info['ttl']}")
    if info.get("is_fragmented"):
        if info.get("ip_id") is not None:
            parts.append(f"id={info['ip_id']}")
        parts.append(f"offset={info.get('fragment_offset', 0)}")
        if info.get("more_fragments"):
            parts.append("MF")

    transport = info.get("transport", {})
    if transport:
        parts.extend(summarize_transport(transport))
    elif info.get("protocol"):
        parts.append(f"proto={info['protocol']}")

    if info.get("length") is not None:
        parts.append(f"{info['length']} bytes")
    return " | ".join(parts)


def summarize_transport(info: dict[str, Any]) -> list[str]:
    """Resume ICMP, TCP ou UDP sem analisar payload."""

    protocol = info.get("protocol")

    if protocol == "ICMP":
        parts = ["ICMP"]
        if info.get("name"):
            parts.append(info["name"])
        elif info.get("type") is not None or info.get("code") is not None:
            parts.append(f"type={info.get('type')}")
            parts.append(f"code={info.get('code')}")
        return parts

    if protocol == "TCP":
        tcp_label = "TCP"
        if info.get("flags"):
            tcp_label = f"TCP [{info['flags']}]"
        return append_service_hint([tcp_label], info)

    if protocol == "UDP":
        if info.get("detail"):
            return ["UDP", info["detail"]]
        return append_service_hint(["UDP"], info)

    return [f"proto={protocol}"] if protocol else []


def append_service_hint(parts: list[str], info: dict[str, Any]) -> list[str]:
    """Acrescenta o serviço sugerido quando há uma porta conhecida."""

    if info.get("service"):
        parts.append(info["service"])
    return parts
