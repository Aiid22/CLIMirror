"""Configuration and Ubuntu 24.04 production preflight checks."""

from __future__ import annotations

import os
import platform
import shutil
import tomllib
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


FIXED_MCP_URL = "http://127.0.0.1:13337/mcp"


class IDAConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    install_dir: Path = Path("/opt/idapro-9.1")


class MCPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = FIXED_MCP_URL
    startup_timeout_seconds: int = Field(default=60, ge=1, le=300)
    request_timeout_seconds: int = Field(default=900, ge=30, le=3600)

    @field_validator("url")
    @classmethod
    def fixed_local_endpoint(cls, value: str) -> str:
        if value.rstrip("/") != FIXED_MCP_URL:
            raise ValueError(f"MCP endpoint must be {FIXED_MCP_URL}")
        return FIXED_MCP_URL


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url: str = "https://api.deepseek.com"
    api_key: str = Field(default="", repr=False)
    model: str = "deepseek-v4-pro"
    timeout_seconds: int = Field(default=90, ge=5, le=600)
    max_output_tokens: int = Field(default=2500, ge=128, le=32768)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_retries: int = Field(default=2, ge=0, le=8)


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_steps: int = Field(default=24, ge=4, le=128)
    max_feedback_rounds: int = Field(default=2, ge=0, le=2)


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output_dir: Path = Path("output")
    run_dir: Path = Path("runs")
    max_file_bytes: int = Field(default=100_000_000, ge=1024)
    max_evidence_packages_per_binary: int = Field(default=250, ge=1, le=5000)


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ida: IDAConfig = Field(default_factory=IDAConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agents: AgentConfig = Field(default_factory=AgentConfig)
    run: RunConfig = Field(default_factory=RunConfig)


def load_config(path: Path) -> Config:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Configuration file not found: {path}. Copy config.example.toml to config.toml.")
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    try:
        config = Config.model_validate(raw)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(part) for part in error["loc"]) for error in exc.errors())
        raise ValueError(f"Invalid config.toml fields: {fields}") from None
    base = path.parent
    for name in ("output_dir", "run_dir"):
        value = getattr(config.run, name)
        setattr(config.run, name, (base / value).resolve() if not value.is_absolute() else value.resolve())
    if not config.ida.install_dir.is_absolute():
        config.ida.install_dir = (base / config.ida.install_dir).resolve()
    if not config.llm.api_key.strip():
        raise ValueError("[llm].api_key is empty in config.toml")
    if not config.llm.base_url.startswith("https://"):
        raise ValueError("[llm].base_url must use HTTPS")
    return config


def _ubuntu_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    release = Path("/etc/os-release")
    if release.is_file():
        for line in release.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    return values.get("ID", ""), values.get("VERSION_ID", "")


def preflight(config: Config) -> None:
    """Fail before analysis when the supported production runtime is incomplete."""
    distro, version = _ubuntu_release()
    if platform.system() != "Linux" or distro != "ubuntu" or version != "24.04":
        raise ValueError("CLIMirror production runs require Ubuntu 24.04")
    if platform.python_version_tuple()[:2] != ("3", "12"):
        raise ValueError("CLIMirror requires Python 3.12")
    if shutil.which("uv") is None:
        raise ValueError("uv was not found on PATH")
    parsed = urlparse(config.mcp.url)
    if (parsed.scheme, parsed.hostname, parsed.port, parsed.path) != ("http", "127.0.0.1", 13337, "/mcp"):
        raise ValueError(f"MCP endpoint must be {FIXED_MCP_URL}")
    directory = config.ida.install_dir.expanduser()
    if not directory.is_dir():
        raise ValueError(f"IDA installation directory not found: {directory}")
    candidates = (directory / "idalib", directory / "python" / "3" / "idalib")
    if not any(candidate.exists() for candidate in candidates):
        raise ValueError(f"IDA idalib was not found under: {directory}")
    if not os.access(directory, os.R_OK | os.X_OK):
        raise ValueError(f"IDA installation is not readable: {directory}")

