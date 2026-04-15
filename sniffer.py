#!/usr/bin/env python3
"""Base de um packet sniffer académico usando Scapy.

Este módulo implementa apenas a fundação da aplicação: interface de linha de
comandos, escolha da fonte de captura, construção de filtros BPF, captura live,
leitura offline de ficheiros PCAP e escrita opcional da captura crua.

As responsabilidades mais avançadas, como parsing detalhado de protocolos,
rastreio de flows ou exportação estruturada de logs, ficam deliberadamente fora
desta etapa para manter a base simples e evolutiva.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


SUPPORTED_PROTOCOLS = {"arp", "ip", "icmp", "tcp", "udp"}
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


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


@dataclass(frozen=True)
class FriendlyFilters:
    """Agrupa os filtros simples que podem ser avaliados diretamente em Python."""

    ip: Optional[str] = None
    mac: Optional[str] = None
    protocol: Optional[str] = None


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Lê e interpreta os argumentos da linha de comandos."""

    parser = argparse.ArgumentParser(
        description="Packet sniffer académico em Python com Scapy."
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


def get_friendly_filters(args: argparse.Namespace) -> FriendlyFilters:
    """Extrai os filtros simples configurados pelo utilizador."""

    return FriendlyFilters(ip=args.ip, mac=args.mac, protocol=args.protocol)


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


def handle_packet(packet: Any, context: CaptureContext) -> None:
    """Processa um pacote capturado ou carregado.

    Nesta etapa o processamento é intencionalmente mínimo: incrementa o contador,
    escreve o pacote em PCAP se aplicável e imprime uma linha curta de teste.
    """

    context.packet_count += 1

    if context.writer is not None:
        context.writer.write(packet)

    action = "capturado" if context.source_type == "live" else "carregado"
    source = (
        context.source_name
        if context.source_type == "live"
        else Path(context.source_name).name
    )
    print(f"[{context.source_type}:{source}] pacote #{context.packet_count} {action}")


def run_live_capture(args: argparse.Namespace, bpf_filter: str) -> CaptureContext:
    """Executa uma captura em tempo real numa interface de rede."""

    _, PcapWriter, sniff, Scapy_Exception = require_scapy()
    context = CaptureContext(
        source_type="live",
        source_name=args.interface,
        bpf_filter=bpf_filter,
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


def run_offline_capture(args: argparse.Namespace, bpf_filter: str) -> CaptureContext:
    """Lê pacotes de um ficheiro PCAP e processa-os em Python."""

    PcapReader, _, _, Scapy_Exception = require_scapy()
    context = CaptureContext(
        source_type="offline",
        source_name=args.pcap,
        bpf_filter=bpf_filter,
    )
    friendly_filters = get_friendly_filters(args)

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


def print_summary(context: CaptureContext) -> None:
    """Imprime um resumo curto da execução."""

    print("\nResumo:")
    print(f"  tipo de fonte: {context.source_type}")
    print(f"  fonte: {context.source_name}")
    print(f"  filtro configurado: {context.bpf_filter or '(sem filtro)'}")
    print(f"  pacotes processados: {context.packet_count}")


def main(argv: Optional[list[str]] = None) -> int:
    """Ponto de entrada da aplicação."""

    args = parse_args(argv)
    validate_args(args)
    bpf_filter = build_bpf_filter(args)

    if args.interface:
        context = run_live_capture(args, bpf_filter)
    else:
        context = run_offline_capture(args, bpf_filter)

    print_summary(context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
