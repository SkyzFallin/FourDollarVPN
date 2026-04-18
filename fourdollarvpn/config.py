"""Persistent user config for FourDollarVPN.

Stores the DigitalOcean API token so users don't have to re-export
DO_API_TOKEN or pass --token on every command. JSON format (stdlib
only, no extra deps).

Location:
    - Linux / macOS: $XDG_CONFIG_HOME/fourdollarvpn/config.json
                     or ~/.config/fourdollarvpn/config.json
    - Windows:       %LOCALAPPDATA%/fourdollarvpn/config.json
                     (not %APPDATA% — Roaming is OneDrive-synced via Known
                     Folder Move, which would silently upload the user's DO
                     token. A one-time migration moves the old file if it
                     existed.)

File perms are forced to 0600 on POSIX. The directory is forced to 0700.
"""

from __future__ import annotations

import json
import os


def config_dir() -> str:
    if os.name == "nt":
        base = (
            os.environ.get("LOCALAPPDATA")
            or os.environ.get("APPDATA")
            or os.path.expanduser("~")
        )
        return os.path.join(base, "fourdollarvpn")
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "fourdollarvpn")
    return os.path.join(os.path.expanduser("~"), ".config", "fourdollarvpn")


def _legacy_config_dir_windows() -> str | None:
    """Old %APPDATA%\\fourdollarvpn path — migrated from on Windows only."""
    if os.name != "nt":
        return None
    base = os.environ.get("APPDATA")
    if not base:
        return None
    return os.path.join(base, "fourdollarvpn")


def config_path() -> str:
    return os.path.join(config_dir(), "config.json")


def _migrate_legacy_config() -> None:
    """One-time move of the old Roaming-AppData config into LOCALAPPDATA.

    Safe to call repeatedly: no-op unless the old file exists and the new
    one doesn't.
    """
    if os.name != "nt":
        return
    legacy_dir = _legacy_config_dir_windows()
    if not legacy_dir:
        return
    new_dir = config_dir()
    if os.path.abspath(legacy_dir) == os.path.abspath(new_dir):
        return
    legacy_path = os.path.join(legacy_dir, "config.json")
    new_path = os.path.join(new_dir, "config.json")
    if os.path.exists(legacy_path) and not os.path.exists(new_path):
        os.makedirs(new_dir, exist_ok=True)
        try:
            os.replace(legacy_path, new_path)
        except OSError:
            pass


def load_config() -> dict:
    """Read the config file. Returns {} if missing or unreadable."""
    _migrate_legacy_config()
    path = config_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(cfg: dict) -> str:
    """Atomically persist `cfg` as JSON with 0600 perms. Returns the path."""
    _migrate_legacy_config()
    d = config_dir()
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass

    path = config_path()
    tmp = path + ".tmp"

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(tmp, flags, 0o600)
    except FileExistsError:
        # Stale .tmp (crashed run) or pre-placed attacker file — remove and
        # retry exactly once. If it reappears between unlink and re-open we
        # let the second FileExistsError propagate rather than loop.
        os.unlink(tmp)
        fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")

    os.replace(tmp, path)
    if os.name != "nt":
        os.chmod(path, 0o600)
    return path
