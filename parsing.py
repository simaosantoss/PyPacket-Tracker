"""Parsing e resumo textual dos pacotes suportados pelo sniffer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


IP_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "ACK": 0x10}


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

    return {
        "src_ip": getattr(ipv4, "src", None),
        "dst_ip": getattr(ipv4, "dst", None),
        "ttl": getattr(ipv4, "ttl", None),
        "length": getattr(ipv4, "len", None),
        "protocol": protocol,
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
    }


def format_ethertype(value: Any) -> Optional[str]:
    """Formata o EtherType de forma curta e reconhecível."""

    if value is None:
        return None
    if isinstance(value, int):
        return f"0x{value:04x}"
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


def summarize_packet(packet: Any) -> str:
    """Cria uma linha curta com o resumo suportado do pacote."""

    try:
        info = extract_packet_info(packet)
    except Exception:
        return "Outro | pacote incompleto ou não suportado nesta fase"

    if "arp" in info:
        return summarize_arp(info["arp"])
    if "ipv4" in info:
        return summarize_ipv4(info["ipv4"])

    ethernet_info = info.get("ethernet", {})
    ethertype = ethernet_info.get("ethertype")
    if ethertype:
        return f"Outro | ethertype={ethertype} | tipo não suportado nesta fase"
    return "Outro | tipo não suportado nesta fase"


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
        return append_service_hint(["UDP"], info)

    return [f"proto={protocol}"] if protocol else []


def append_service_hint(parts: list[str], info: dict[str, Any]) -> list[str]:
    """Acrescenta o serviço sugerido quando há uma porta conhecida."""

    if info.get("service"):
        parts.append(info["service"])
    return parts
