#!/usr/bin/env python3
"""Ponto de entrada do packet sniffer académico com Scapy."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from typing import Any, Optional

from capture import CaptureContext, run_live_capture, run_offline_capture
from logging_output import (
    SUPPORTED_LOG_FORMATS,
    open_packet_logger,
    validate_log_path,
)
from parsing import FriendlyFilters
from stats import format_stats_report


SUPPORTED_PROTOCOLS = {"arp", "ip", "icmp", "tcp", "udp"}
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Lê e interpreta os argumentos da linha de comandos."""

    parser = argparse.ArgumentParser(
        description="Packet sniffer em Python com Scapy.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=45),
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="interface de rede para captura em tempo real",
    )
    parser.add_argument(
        "-r",
        "--pcap",
        help="caminho para um ficheiro .pcap para leitura offline",
    )
    parser.add_argument(
        "--bpf",
        help="expressão BPF bruta, por exemplo: 'tcp port 80'",
    )
    parser.add_argument("--ip", help="filtrar por endereço IP")
    parser.add_argument("--mac", help="filtrar por endereço MAC")
    parser.add_argument(
        "--protocol",
        help="filtrar por protocolo: arp, ip, icmp, tcp ou udp",
    )
    parser.add_argument(
        "--write-pcap",
        help="ficheiro .pcap de saída para guardar a captura crua em modo live",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="número máximo de pacotes a processar (0 significa sem limite)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="tempo limite da captura live, em segundos",
    )
    parser.add_argument("--log-file", help="ficheiro de saída para logging estruturado")
    parser.add_argument(
        "--log-format",
        choices=sorted(SUPPORTED_LOG_FORMATS),
        help="formato do log: txt, csv ou json",
    )

    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    """Valida os argumentos e termina com uma mensagem clara em caso de erro."""

    errors: list[str] = []

    if bool(args.interface) == bool(args.pcap):
        errors.append(
            "indica exatamente uma fonte de captura: usa --interface ou --pcap, "
            "mas não ambas."
        )

    if args.ip:
        try:
            ipaddress.ip_address(args.ip)
        except ValueError:
            errors.append(f"endereço IP inválido: {args.ip!r}.")

    if args.mac and not MAC_RE.fullmatch(args.mac):
        errors.append(
            f"endereço MAC inválido: {args.mac!r}. Usa o formato aa:bb:cc:dd:ee:ff."
        )

    if args.protocol:
        args.protocol = args.protocol.lower()
        if args.protocol not in SUPPORTED_PROTOCOLS:
            supported = ", ".join(sorted(SUPPORTED_PROTOCOLS))
            errors.append(
                f"protocolo não suportado: {args.protocol!r}. "
                f"Protocolos suportados: {supported}."
            )

    if args.count < 0:
        errors.append("--count não pode ser negativo.")

    if args.timeout is not None and args.timeout <= 0:
        errors.append("--timeout tem de ser maior do que zero.")

    if args.pcap and not args.interface:
        pcap_path = Path(args.pcap)
        if not pcap_path.is_file():
            errors.append(f"ficheiro PCAP não encontrado: {args.pcap!r}.")

    if args.pcap and not args.interface and args.bpf:
        errors.append(
            "o BPF bruto em modo offline não é suportado nesta base de forma "
            "previsível. Usa filtros amigáveis no PCAP ou usa --bpf em modo live."
        )

    if args.write_pcap and args.pcap:
        errors.append("--write-pcap só é suportado em modo live com --interface.")

    if args.write_pcap:
        output_path = Path(args.write_pcap)
        if output_path.exists() and output_path.is_dir():
            errors.append(
                f"--write-pcap aponta para uma diretoria: {args.write_pcap!r}."
            )
        if output_path.suffix.lower() != ".pcap":
            errors.append(
                "--write-pcap deve apontar para um ficheiro com extensão .pcap."
            )
        parent = output_path.parent
        if parent and not parent.exists():
            errors.append(
                f"diretoria de saída não existe para --write-pcap: {str(parent)!r}."
            )

    if bool(args.log_file) != bool(args.log_format):
        errors.append("--log-file e --log-format têm de ser usados em conjunto.")

    if args.log_format and args.log_format not in SUPPORTED_LOG_FORMATS:
        supported = ", ".join(sorted(SUPPORTED_LOG_FORMATS))
        errors.append(f"formato de log inválido. Formatos suportados: {supported}.")

    if args.log_file:
        log_path_error = validate_log_path(args.log_file)
        if log_path_error:
            errors.append(log_path_error)

    if errors:
        for error in errors:
            print(f"Erro: {error}", file=sys.stderr)
        raise SystemExit(2)


def build_bpf_filter(args: argparse.Namespace) -> str:
    """Constrói a expressão de filtro configurada pelo utilizador."""

    parts: list[str] = []

    if args.bpf:
        parts.append(args.bpf.strip())
    if args.ip:
        parts.append(f"host {args.ip}")
    if args.mac:
        parts.append(f"ether host {args.mac}")
    if args.protocol:
        parts.append(args.protocol)

    # Cada parte fica isolada para preservar a precedência quando há BPF bruto.
    return " and ".join(f"({part})" for part in parts if part)


def get_friendly_filters(args: argparse.Namespace) -> FriendlyFilters:
    """Extrai os filtros simples configurados pelo utilizador."""

    return FriendlyFilters(ip=args.ip, mac=args.mac, protocol=args.protocol)


def print_summary(context: CaptureContext) -> None:
    """Imprime um resumo curto da execução."""

    print("\nResumo:")
    print(f"  tipo de fonte: {context.source_type}")
    print(f"  fonte: {context.source_name}")
    print(f"  filtro configurado: {context.bpf_filter or '(sem filtro)'}")
    print(f"  pacotes processados: {context.packet_count}")
    print(format_stats_report(context.stats_state, context.packet_count))


def main(argv: Optional[list[str]] = None) -> int:
    """Ponto de entrada da aplicação."""

    args = parse_args(argv)
    validate_args(args)
    bpf_filter = build_bpf_filter(args)
    logger: Optional[Any] = None

    try:
        if args.log_file:
            logger = open_packet_logger(args.log_file, args.log_format)

        if args.interface:
            context = run_live_capture(args, bpf_filter, logger)
        else:
            friendly_filters = get_friendly_filters(args)
            context = run_offline_capture(args, bpf_filter, friendly_filters, logger)

        print_summary(context)
        return 0
    finally:
        if logger is not None:
            logger.close()


if __name__ == "__main__":
    raise SystemExit(main())
