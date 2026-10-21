"""Configuration loader for the Windows endpoint agent."""

import dataclasses
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ENV_VAR_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")


def _expand_env_vars(val: Any) -> Any:
    """Recursively expands ${VAR:-default} and ${VAR} patterns in strings, lists, and dicts."""
    if isinstance(val, str):
        def repl(match: re.Match) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default_val)

        return ENV_VAR_PATTERN.sub(repl, val)
    elif isinstance(val, list):
        return [_expand_env_vars(item) for item in val]
    elif isinstance(val, dict):
        return {k: _expand_env_vars(v) for k, v in val.items()}
    return val


def _load_dotenv_if_present(base_dir: Path) -> None:
    """Loads .env from project root or base_dir into os.environ if not already set."""
    search_dirs = [base_dir, base_dir.parent, Path.cwd()]
    for d in search_dirs:
        env_file = d / ".env"
        if env_file.is_file():
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass


@dataclass
class ChannelConfig:
    """Configuration for a specific Windows Event Log channel."""
    name: str
    event_ids: List[int] = field(default_factory=list)
    description: str = ""

    def build_xpath_query(self) -> str:
        """Constructs an XPath query to retrieve only the configured Event IDs."""
        if not self.event_ids:
            return "*"
        id_clauses = " or ".join([f"EventID={eid}" for eid in self.event_ids])
        return f"*[System[({id_clauses})]]"


@dataclass
class AgentConfig:
    """Full runtime configuration for the Windows endpoint agent."""
    device_id: str = "PC-LAB-01"
    api_endpoint: str = ""
    api_key: str = ""
    channels: List[ChannelConfig] = field(default_factory=list)
    poll_interval_seconds: int = 5
    batch_size: int = 100
    batch_interval_seconds: int = 30
    heartbeat_interval_seconds: int = 120
    bookmark_file: Path = Path("./data/bookmarks.json")
    queue_file: Path = Path("./data/queue.sqlite")
    local_db_file: Path = Path("./data/local_alerts.sqlite")
    log_file: Path = Path("./logs/agent.log")
    log_max_bytes: int = 5242880
    log_backup_count: int = 3
    log_level: str = "INFO"
    standalone_mode: bool = False
    rules_file: Path = dataclasses.field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"
    )
    whitelist_file: Path = dataclasses.field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "rules" / "whitelist.yaml"
    )


def load_config(config_path: Optional[Path] = None) -> AgentConfig:
    """Loads configuration from YAML, expanding environment variables and resolving paths."""
    if config_path is None:
        # Default to agent/config.yaml
        config_path = Path(__file__).parent / "config.yaml"

    config_path = Path(config_path).resolve()
    base_dir = config_path.parent

    # Try loading .env if present
    _load_dotenv_if_present(base_dir)

    raw_data: Dict[str, Any] = {}
    if config_path.is_file():
        with open(config_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                raw_data = loaded

    # Expand environment variables
    data = _expand_env_vars(raw_data)

    def resolve_path(p_str: Optional[str], default_rel: str) -> Path:
        val = p_str if p_str else default_rel
        path_obj = Path(val)
        if not path_obj.is_absolute():
            path_obj = (base_dir / path_obj).resolve()
        return path_obj

    # Parse channels
    channels: List[ChannelConfig] = []
    for ch in data.get("channels", []):
        if isinstance(ch, dict) and "name" in ch:
            channels.append(
                ChannelConfig(
                    name=str(ch["name"]),
                    event_ids=[int(eid) for eid in ch.get("event_ids", [])],
                    description=str(ch.get("description", "")),
                )
            )

    return AgentConfig(
        device_id=str(data.get("device_id") or os.environ.get("DEVICE_ID") or "PC-LAB-01"),
        api_endpoint=str(data.get("api_endpoint") or os.environ.get("API_ENDPOINT") or ""),
        api_key=str(data.get("api_key") or os.environ.get("API_KEY") or ""),
        channels=channels,
        poll_interval_seconds=int(data.get("poll_interval_seconds", 5)),
        batch_size=int(data.get("batch_size", 100)),
        batch_interval_seconds=int(data.get("batch_interval_seconds", 30)),
        heartbeat_interval_seconds=int(data.get("heartbeat_interval_seconds", 120)),
        bookmark_file=resolve_path(data.get("bookmark_file"), "./data/bookmarks.json"),
        queue_file=resolve_path(data.get("queue_file"), "./data/queue.sqlite"),
        local_db_file=resolve_path(data.get("local_db_file"), "./data/local_alerts.sqlite"),
        log_file=resolve_path(data.get("log_file"), "./logs/agent.log"),
        log_max_bytes=int(data.get("log_max_bytes", 5242880)),
        log_backup_count=int(data.get("log_backup_count", 3)),
        log_level=str(data.get("log_level", "INFO")),
        standalone_mode=str(data.get("standalone_mode", "false")).lower() in ("true", "1", "yes"),
        rules_file=resolve_path(data.get("rules_file"), "../rules/rules.yaml"),
        whitelist_file=resolve_path(data.get("whitelist_file"), "../rules/whitelist.yaml"),
    )
