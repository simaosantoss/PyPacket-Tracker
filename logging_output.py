"""Escrita simples de logs estruturados em TXT, CSV ou JSON Lines."""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


SUPPORTED_LOG_FORMATS = {"txt", "csv", "json"}
CSV_FIELDS = [
    "packet_number",
    "timestamp",
    "source_type",
    "source_name",
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "ttl",
    "length",
    "ip_id",
    "fragment_offset",
    "more_fragments",
    "service",
    "summary",
]


@dataclass
class PacketLogger:
    """Mantém o ficheiro de log aberto e escreve no formato escolhido."""

    path: str
    log_format: str
    file: Any
    csv_writer: Optional[csv.DictWriter] = None

    def write_packet(self, record: dict[str, Any]) -> None:
        """Escreve um pacote no ficheiro de log."""

        try:
            if self.log_format == "txt":
                self.file.write(format_txt_record(record) + "\n")
            elif self.log_format == "csv":
                assert self.csv_writer is not None
                self.csv_writer.writerow(
                    {field: record.get(field, "") for field in CSV_FIELDS}
                )
            elif self.log_format == "json":
                self.file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.file.flush()
        except OSError as exc:
            print(
                f"Erro ao escrever no ficheiro de log {self.path!r}: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc

    def close(self) -> None:
        """Fecha o ficheiro de log."""

        self.file.close()


def format_packet_line(record: dict[str, Any]) -> str:
    """Formata uma linha curta para consola ou TXT."""

    parts: list[str] = []

    packet_number = record.get("packet_number")
    if packet_number not in (None, ""):
        parts.append(f"[{packet_number}]")

    source_display = record.get("source_display")
    if source_display:
        parts.append(f"[{source_display}]")

    timestamp_display = record.get("timestamp_display")
    if timestamp_display:
        parts.append(f"[{timestamp_display}]")

    summary = record.get("summary")
    if summary:
        parts.append(str(summary))

    return " ".join(parts)


def open_packet_logger(path: str, log_format: str) -> PacketLogger:
    """Abre o ficheiro de log e prepara o escritor adequado."""

    try:
        file = open(path, "w", encoding="utf-8", newline="")
    except OSError as exc:
        print(f"Erro ao abrir ficheiro de log {path!r}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    logger = PacketLogger(path=path, log_format=log_format, file=file)
    if log_format == "csv":
        logger.csv_writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        logger.csv_writer.writeheader()
        file.flush()

    return logger


def format_txt_record(record: dict[str, Any]) -> str:
    """Formata uma linha TXT curta, semelhante ao output da consola."""

    return format_packet_line(record)


def validate_log_path(path: str) -> Optional[str]:
    """Valida o caminho de log sem abrir o ficheiro."""

    output_path = Path(path)
    if output_path.exists() and output_path.is_dir():
        return f"--log-file aponta para uma diretoria: {path!r}."

    parent = output_path.parent
    if parent and not parent.exists():
        return f"diretoria de saída não existe para --log-file: {str(parent)!r}."

    return None
