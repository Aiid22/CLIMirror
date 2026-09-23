"""Exact `.dynsym` import/export indexing for cross-library candidates."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class DynamicSymbol:
    name: str
    value: int
    defined: bool


@dataclass(frozen=True)
class CrossLibraryCandidate:
    source_path: str
    target_path: str
    symbol: str
    target_address: int


def read_dynsym(path: Path) -> list[DynamicSymbol]:
    from elftools.elf.elffile import ELFFile

    values: list[DynamicSymbol] = []
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".dynsym")
        if section is None:
            return []
        for symbol in section.iter_symbols():
            name = symbol.name
            if not name:
                continue
            defined = symbol["st_shndx"] != "SHN_UNDEF"
            values.append(DynamicSymbol(name=name, value=int(symbol["st_value"]), defined=defined))
    return values


class ELFSymbolIndex:
    """Allows only a unique exact import/export name match."""

    def __init__(self, files: Iterable[tuple[str, Path]]):
        self.symbols: dict[str, list[DynamicSymbol]] = {}
        for relative_path, path in files:
            try:
                self.symbols[relative_path] = read_dynsym(path)
            except Exception:
                # IDA may still understand an unusual/truncated ELF. Cross-library
                # recovery is disabled for this file rather than failing the run.
                self.symbols[relative_path] = []
        exports: dict[str, list[tuple[str, DynamicSymbol]]] = {}
        for relative_path, symbols in self.symbols.items():
            for symbol in symbols:
                if symbol.defined:
                    exports.setdefault(symbol.name, []).append((relative_path, symbol))
        self.unique_exports = {name: items[0] for name, items in exports.items() if len(items) == 1}

    def candidates_for(self, source_path: str) -> list[CrossLibraryCandidate]:
        candidates: list[CrossLibraryCandidate] = []
        seen: set[tuple[str, str]] = set()
        for symbol in self.symbols.get(source_path, []):
            if symbol.defined or symbol.name not in self.unique_exports:
                continue
            target_path, target = self.unique_exports[symbol.name]
            key = (target_path, symbol.name)
            if target_path == source_path or key in seen:
                continue
            seen.add(key)
            candidates.append(CrossLibraryCandidate(source_path, target_path, symbol.name, target.value))
        return sorted(candidates, key=lambda item: (item.symbol, item.target_path))

