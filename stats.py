"""Estatísticas finais simples para a execução do sniffer."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


KNOWN_PROTOCOLS = {"ARP", "ICMP", "TCP", "UDP"}


@dataclass
class StatsState:
    """Guarda contadores simples atualizados durante a captura."""

    protocol_counts: Counter[str] = field(default_factory=Counter)
    source_ip_counts: Counter[str] = field(default_factory=Counter)
    event_counts: Counter[str] = field(default_factory=Counter)


def update_packet_stats(state: StatsState, record: dict[str, Any]) -> None:
    """Atualiza estatísticas com base no registo achatado de um pacote."""

    protocol = classify_protocol(record)
    state.protocol_counts[protocol] += 1

    src_ip = record.get("src_ip")
    if src_ip:
        state.source_ip_counts[str(src_ip)] += 1


def update_event_stats(state: StatsState, events: list[str]) -> None:
    """Atualiza contadores de eventos do tracker."""

    for event in events:
        event_name = extract_event_name(event)
        if event_name:
            state.event_counts[event_name] += 1


def classify_protocol(record: dict[str, Any]) -> str:
    """Classifica o protocolo principal para o relatório final."""

    protocol = record.get("protocol")
    if protocol in KNOWN_PROTOCOLS:
        return protocol
    if record.get("src_ip") or record.get("dst_ip"):
        return "IPv4"
    return "Outro"


def extract_event_name(event: str) -> str:
    """Extrai o nome curto de uma linha de evento."""

    prefix = "[evento] "
    if not event.startswith(prefix):
        return ""
    return event.removeprefix(prefix).split("|", maxsplit=1)[0].strip()


def format_stats_report(state: StatsState, total_packets: int) -> str:
    """Formata o relatório final de estatísticas."""

    lines = ["", "Estatísticas:", "  protocolos:"]
    lines.extend(format_protocol_stats(state, total_packets))
    lines.extend(["", "  top talkers:"])
    lines.extend(format_top_talkers(state))
    lines.extend(["", "  eventos:"])
    lines.extend(format_event_stats(state))
    return "\n".join(lines)


def format_protocol_stats(state: StatsState, total_packets: int) -> list[str]:
    """Formata contagens e percentagens por protocolo."""

    order = ["ARP", "ICMP", "TCP", "UDP", "IPv4", "Outro"]
    lines: list[str] = []

    for protocol in order:
        count = state.protocol_counts.get(protocol, 0)
        if count == 0:
            continue
        percentage = (count / total_packets * 100) if total_packets else 0
        lines.append(f"    {protocol}: {count} ({percentage:.1f}%)")

    return lines or ["    (sem pacotes classificados)"]


def format_top_talkers(state: StatsState) -> list[str]:
    """Formata os três IPs de origem mais frequentes."""

    top_talkers = state.source_ip_counts.most_common(3)
    if not top_talkers:
        return ["    (sem IPs de origem)"]

    return [
        f"    {position}. {ip_address} - {format_packet_count(count)}"
        for position, (ip_address, count) in enumerate(top_talkers, start=1)
    ]


def format_event_stats(state: StatsState) -> list[str]:
    """Formata contadores de eventos detetados."""

    if not state.event_counts:
        return ["    (sem eventos detetados)"]

    return [
        f"    {event_name}: {count}"
        for event_name, count in state.event_counts.items()
    ]


def format_packet_count(count: int) -> str:
    """Formata a contagem de pacotes com singular/plural correto."""

    suffix = "pacote" if count == 1 else "pacotes"
    return f"{count} {suffix}"
