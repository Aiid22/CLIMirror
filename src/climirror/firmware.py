"""Read-only discovery of ELF files in an unpacked firmware tree."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path


CLI_TERMS = (
    b"invalid command", b"ambiguous command", b"unknown command",
    b"command not found", b"configure terminal", b"(config)#",
    b"show ", b"enable", b"disable", b"help", b"usage:", b"cli",
)
NAME_TERMS = ("cli", "shell", "cmd", "console", "telnet", "ssh", "admin", "config")


@dataclass(frozen=True)
class FirmwareBinary:
    absolute_path: Path
    relative_path: str
    size: int
    coarse_score: int
    sha256: str


def validate_firmware_root(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("--firmware must be an absolute directory path")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"Firmware input is not a directory: {resolved}")
    return resolved


def safe_firmware_name(root: Path) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", root.name).strip(" .")
    return name or "firmware"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def scan_elf_files(root: Path, max_file_bytes: int) -> tuple[list[FirmwareBinary], list[tuple[str, str]]]:
    files: list[FirmwareBinary] = []
    skipped: list[tuple[str, str]] = []
    for parent, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(parent) / name).is_symlink()
                   and not getattr(Path(parent) / name, "is_junction", lambda: False)()
                   and (Path(parent) / name).resolve().is_relative_to(root)]
        for name in sorted(names):
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                skipped.append((relative, "symlink, outside root or non-regular file"))
                continue
            try:
                size = path.stat().st_size
                if size < 64 or size > max_file_bytes:
                    skipped.append((relative, "outside configured ELF size bounds"))
                    continue
                with path.open("rb") as stream:
                    sample = stream.read(min(size, 4 * 1024 * 1024))
                if not sample.startswith(b"\x7fELF"):
                    continue
                name_score = sum(term in name.lower() for term in NAME_TERMS)
                lowered = sample.lower()
                lexical_score = sum(term in lowered for term in CLI_TERMS)
                files.append(FirmwareBinary(path, relative, size, name_score + lexical_score, _hash_file(path)))
            except OSError as exc:
                skipped.append((relative, f"file read error: {type(exc).__name__}"))
    files.sort(key=lambda item: (-item.coarse_score, item.relative_path))
    return files, skipped
