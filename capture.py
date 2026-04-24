"""Execução da captura live/offline e callback por pacote."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from logging_output import format_packet_line
from parsing import (
    FriendlyFilters,
    build_log_record,
    extract_packet_info,
    packet_matches_friendly_filters,
    summarize_packet,
)
from stats import StatsState, update_event_stats, update_packet_stats
from tracking import TrackerState, process_packet_tracking


@dataclass
class CaptureContext:
    """Guarda o estado mínimo de execução da captura.

    A classe existe para evitar variáveis globais e para facilitar extensões
    futuras, por exemplo estatísticas por protocolo ou escrita estruturada.
    """

    source_type: str
    source_name: str
    bpf_filter: str
    packet_count: int = 0
    writer: Optional[Any] = None
    packet_logger: Optional[Any] = None
    tracker_state: TrackerState = field(default_factory=TrackerState)
    stats_state: StatsState = field(default_factory=StatsState)
    packet_history: list[dict[str, Any]] = field(default_factory=list)


def require_scapy() -> tuple[Any, Any, Any, type[Exception]]:
    """Carrega os componentes do Scapy apenas quando são necessários.

    Isto permite que a ajuda da CLI funcione mesmo num ambiente onde a
    dependência ainda não foi instalada, mantendo uma mensagem de erro limpa
    quando o utilizador tenta capturar ou ler pacotes.
    """

    try:
        from scapy.all import PcapReader, PcapWriter, sniff
        from scapy.error import Scapy_Exception
    except ModuleNotFoundError as exc:
        if exc.name != "scapy":
            raise
        print(
            "Erro: o Scapy não está instalado. Instala a dependência com "
            "'python3 -m pip install scapy' e volta a executar o programa.",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    return PcapReader, PcapWriter, sniff, Scapy_Exception


def source_label(context: CaptureContext) -> str:
    """Constrói o prefixo que identifica a origem da captura."""

    source = (
        context.source_name
        if context.source_type == "live"
        else Path(context.source_name).name
    )
    return f"[{context.source_type}:{source}]"


def handle_packet(packet: Any, context: CaptureContext) -> None:
    """Processa um pacote capturado ou carregado.

    Nesta etapa o processamento identifica Ethernet, ARP, IPv4 e detalhes
    essenciais de ICMP, TCP e UDP.
    """

    context.packet_count += 1

    if context.writer is not None:
        context.writer.write(packet)

    events, annotations = process_packet_tracking(
        packet, context.tracker_state, context.packet_count
    )

    try:
        packet_info = extract_packet_info(packet)
    except Exception:
        packet_info = {}

    summary = summarize_packet(packet, annotations, packet_info)
    record = build_log_record(
        packet,
        context.source_type,
        context.source_name,
        context.packet_count,
        summary,
        packet_info,
    )
    context.packet_history.append({"record": record, "info": packet_info})
    print(format_packet_line(record))

    update_packet_stats(context.stats_state, record)

    if context.packet_logger is not None:
        context.packet_logger.write_packet(record)

    update_event_stats(context.stats_state, events)

    for event in events:
        print(event)


def run_live_capture(
    args: Any, bpf_filter: str, packet_logger: Optional[Any] = None
) -> CaptureContext:
    """Executa uma captura em tempo real numa interface de rede."""

    _, PcapWriter, sniff, Scapy_Exception = require_scapy()
    context = CaptureContext(
        source_type="live",
        source_name=args.interface,
        bpf_filter=bpf_filter,
        packet_logger=packet_logger,
    )

    try:
        if args.write_pcap:
            context.writer = PcapWriter(args.write_pcap, append=False, sync=True)

        sniff(
            iface=args.interface,
            filter=bpf_filter or None,
            prn=lambda packet: handle_packet(packet, context),
            store=False,
            count=args.count,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo utilizador.")
    except PermissionError as exc:
        print(
            "Erro: permissões insuficientes para capturar pacotes. "
            "Experimenta executar com privilégios adequados.",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    except Scapy_Exception as exc:
        print(f"Erro na captura live: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except OSError as exc:
        print(f"Erro de sistema na captura live: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    finally:
        if context.writer is not None:
            context.writer.close()

    return context


def run_offline_capture(
    args: Any,
    bpf_filter: str,
    friendly_filters: FriendlyFilters,
    packet_logger: Optional[Any] = None,
) -> CaptureContext:
    """Lê pacotes de um ficheiro PCAP e processa-os em Python."""

    PcapReader, _, _, Scapy_Exception = require_scapy()
    context = CaptureContext(
        source_type="offline",
        source_name=args.pcap,
        bpf_filter=bpf_filter,
        packet_logger=packet_logger,
    )

    try:
        with PcapReader(args.pcap) as reader:
            for packet in reader:
                if not packet_matches_friendly_filters(packet, friendly_filters):
                    continue

                handle_packet(packet, context)

                if args.count and context.packet_count >= args.count:
                    break
    except KeyboardInterrupt:
        print("\nLeitura offline interrompida pelo utilizador.")
    except Scapy_Exception as exc:
        print(f"Erro ao ler o ficheiro PCAP: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except OSError as exc:
        print(f"Erro ao abrir o ficheiro PCAP: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    return context
