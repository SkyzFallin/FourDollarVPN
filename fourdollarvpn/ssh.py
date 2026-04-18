from __future__ import annotations

import os
import re
import threading
import time

import paramiko
from rich.console import Console

console = Console()

SSH_TIMEOUT = 10
SSH_MAX_RETRIES = 30
SSH_RETRY_DELAY = 10

# Per-user trust store for FourDollarVPN-managed hosts.
# Deliberately kept separate from ~/.ssh/known_hosts so we never touch the
# user's regular SSH state and stale entries from destroyed droplets don't
# leak into unrelated sessions.
#
# On Windows this lives under %LOCALAPPDATA%\fourdollarvpn (not %USERPROFILE%),
# because %USERPROFILE% is OneDrive-KFM-synced — a stray host key or
# private SSH key landing there gets uploaded to Microsoft.
def _fourdollarvpn_data_dir() -> str:
    if os.name == "nt":
        base = (
            os.environ.get("LOCALAPPDATA")
            or os.environ.get("APPDATA")
            or os.path.expanduser("~")
        )
        return os.path.join(base, "fourdollarvpn")
    return os.path.expanduser("~/.fourdollarvpn")


def _legacy_data_dir_windows() -> str | None:
    if os.name != "nt":
        return None
    # Previous builds stored under %USERPROFILE%\.fourdollarvpn — migrate if so.
    return os.path.join(os.path.expanduser("~"), ".fourdollarvpn")


KNOWN_HOSTS_PATH = os.path.join(_fourdollarvpn_data_dir(), "known_hosts")

# Directory of per-droplet SSH private keys. The key generated during
# `fourdollarvpn setup` is the only one the droplet's authorized_keys will
# ever have (DigitalOcean only copies SSH keys into authorized_keys at
# droplet-creation time — adding a key to the account later doesn't
# propagate). So we persist it here after setup so subsequent `check`,
# `add-client`, etc. can actually SSH in.
SERVER_KEYS_DIR = os.path.join(_fourdollarvpn_data_dir(), "servers")


def _migrate_legacy_data_dir() -> None:
    """One-time move of the old %USERPROFILE%\\.fourdollarvpn to %LOCALAPPDATA%."""
    legacy = _legacy_data_dir_windows()
    if not legacy:
        return
    new = _fourdollarvpn_data_dir()
    if os.path.abspath(legacy) == os.path.abspath(new):
        return
    if not os.path.isdir(legacy):
        return
    # If the new dir is absent, move the whole tree. If both exist, only
    # copy files that aren't already present — leaves anything the new
    # location already has untouched.
    if not os.path.isdir(new):
        try:
            os.makedirs(os.path.dirname(new), exist_ok=True)
            os.replace(legacy, new)
            return
        except OSError:
            pass
    for root, _, files in os.walk(legacy):
        rel = os.path.relpath(root, legacy)
        dest_root = os.path.join(new, rel) if rel != "." else new
        os.makedirs(dest_root, exist_ok=True)
        for name in files:
            src = os.path.join(root, name)
            dst = os.path.join(dest_root, name)
            if not os.path.exists(dst):
                try:
                    os.replace(src, dst)
                except OSError:
                    pass


class SSHError(Exception):
    pass


_SECRET_PATTERNS = [
    # WireGuard base64 keys (44 chars, ending '=')
    re.compile(r"[A-Za-z0-9+/]{43}="),
    # DigitalOcean API tokens
    re.compile(r"dop_v1_[a-fA-F0-9]{64}"),
    # PEM-encoded private key blocks
    re.compile(
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
        re.DOTALL,
    ),
]


def redact_secrets(text: str) -> str:
    """Scrub key material and tokens from user-visible strings."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


# Backwards-compatible private alias
_redact_secrets = redact_secrets


def _ensure_known_hosts_dir() -> None:
    _migrate_legacy_data_dir()
    d = os.path.dirname(KNOWN_HOSTS_PATH)
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass


def _ensure_server_keys_dir() -> None:
    _migrate_legacy_data_dir()
    os.makedirs(SERVER_KEYS_DIR, exist_ok=True)
    try:
        os.chmod(SERVER_KEYS_DIR, 0o700)
    except OSError:
        pass


def _droplet_key_path(droplet_id: int | str) -> str:
    """Canonical path: keyed by the DigitalOcean droplet ID.

    DO recycles IPs — binding by IP meant a destroyed-and-recreated
    droplet at the same IP silently inherited the old key's identity.
    """
    return os.path.join(SERVER_KEYS_DIR, f"{droplet_id}.key")


def _legacy_ip_key_path(ip: str) -> str:
    """Pre-v1.0.10 path: {ip}.key. Still read as a fallback for users
    who set up on v1.0.8 / v1.0.9 — migrated to the ID path the next
    time we see the droplet via the DO API."""
    return os.path.join(SERVER_KEYS_DIR, f"{ip}.key")


def save_droplet_key(droplet_id: int | str, openssh_pem: str) -> str:
    """Persist the OpenSSH-formatted SSH private key for droplet
    `droplet_id`. File is written atomically with 0600 perms.

    `openssh_pem` is the raw PEM string (as returned by
    `DigitalOcean.generate_ssh_keypair`) — not a paramiko key object, because
    paramiko's Ed25519Key doesn't implement write_private_key.

    Returns the final path.
    """
    _ensure_server_keys_dir()
    path = _droplet_key_path(droplet_id)
    tmp = path + ".tmp"

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(tmp, flags, 0o600)
    except FileExistsError:
        # Stale .tmp (crashed run) or pre-placed attacker file — remove and
        # retry exactly once. A second FileExistsError is left to propagate.
        os.unlink(tmp)
        fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(openssh_pem)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    if os.name != "nt":
        os.chmod(path, 0o600)
    return path


def load_droplet_key(
    droplet_id: int | str, ip: str | None = None
) -> paramiko.Ed25519Key | None:
    """Return the saved SSH key for `droplet_id`, or None if no key has
    been saved (or the file is unreadable / malformed).

    If a legacy IP-indexed key from v1.0.8 / v1.0.9 exists at
    `{ip}.key` and no ID-indexed key is present yet, load the legacy
    file AND migrate it into place (rename to `{droplet_id}.key`).
    After the rename, subsequent runs find the ID file directly.
    """
    path = _droplet_key_path(droplet_id)
    if not os.path.exists(path) and ip:
        legacy = _legacy_ip_key_path(ip)
        if os.path.exists(legacy):
            try:
                os.replace(legacy, path)
            except OSError:
                # If the rename fails (permission, cross-device), fall
                # back to reading the legacy file in place.
                try:
                    return paramiko.Ed25519Key.from_private_key_file(legacy)
                except Exception:
                    return None
    if not os.path.exists(path):
        return None
    try:
        return paramiko.Ed25519Key.from_private_key_file(path)
    except Exception:
        return None


def forget_droplet_key(
    droplet_id: int | str, ip: str | None = None
) -> None:
    """Remove the saved SSH key for `droplet_id`, if any. Silent if
    missing. Also removes any legacy `{ip}.key` left behind by v1.0.8
    / v1.0.9 — after destroy, neither path should survive."""
    for path in (
        _droplet_key_path(droplet_id),
        _legacy_ip_key_path(ip) if ip else None,
    ):
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def forget_host_key(host: str) -> None:
    """Remove any known_hosts entry for `host`.

    Called before connecting to a freshly-provisioned droplet, since
    DigitalOcean recycles IPs and a stale entry from a prior droplet
    would cause a spurious host-key-mismatch rejection.
    """
    _ensure_known_hosts_dir()
    if not os.path.exists(KNOWN_HOSTS_PATH):
        return
    hk = paramiko.HostKeys()
    try:
        hk.load(KNOWN_HOSTS_PATH)
    except Exception:
        return
    if host in hk:
        del hk[host]
        try:
            hk.save(KNOWN_HOSTS_PATH)
        except OSError:
            pass


class _PinningPolicy(paramiko.MissingHostKeyPolicy):
    """On first contact, silently store the host key and persist it.

    paramiko's built-in HostKeys verification already rejects mismatches
    before this policy is consulted, so this only handles the
    never-seen-before case (true first connect).
    """

    def __init__(self, known_hosts_path: str):
        self.known_hosts_path = known_hosts_path

    def missing_host_key(self, client, hostname, key):
        client.get_host_keys().add(hostname, key.get_name(), key)
        try:
            client.get_host_keys().save(self.known_hosts_path)
            os.chmod(self.known_hosts_path, 0o600)
        except OSError:
            pass


class SSHConnection:
    def __init__(
        self,
        host: str,
        key: paramiko.Ed25519Key,
        username: str = "root",
        fresh: bool = False,
    ):
        """
        fresh=True: assume we're provisioning a new droplet at this IP.
            Forget any stored host key for the IP before connecting, then
            trust-on-first-use and persist the new key.
        fresh=False (default): strict verification. If the host key has
            changed since we saved it, paramiko raises BadHostKeyException
            (surfaced here as SSHError). MITM attempt caught.
        """
        self.host = host
        self.key = key
        self.username = username
        self.fresh = fresh
        self.client: paramiko.SSHClient | None = None

    def connect(self):
        self.client = paramiko.SSHClient()
        _ensure_known_hosts_dir()

        if self.fresh:
            forget_host_key(self.host)

        if os.path.exists(KNOWN_HOSTS_PATH):
            try:
                self.client.load_host_keys(KNOWN_HOSTS_PATH)
            except IOError:
                pass

        self.client.set_missing_host_key_policy(
            _PinningPolicy(KNOWN_HOSTS_PATH)
        )

        for attempt in range(1, SSH_MAX_RETRIES + 1):
            try:
                self.client.connect(
                    hostname=self.host,
                    username=self.username,
                    pkey=self.key,
                    timeout=SSH_TIMEOUT,
                    look_for_keys=False,
                    allow_agent=False,
                )
                return
            except paramiko.AuthenticationException as e:
                # Don't retry auth failures — they won't heal on their own
                raise SSHError(
                    f"SSH authentication failed for {self.username}@{self.host}: {e}"
                ) from e
            except paramiko.BadHostKeyException as e:
                # Host key changed from what we pinned — possible MITM.
                # Fail fast with a clear message. User can recover with
                # `fourdollarvpn setup` (which re-pins) if the droplet was
                # legitimately rebuilt.
                raise SSHError(
                    f"SSH host key for {self.host} does not match the key "
                    f"saved during setup. This could mean the droplet was "
                    f"rebuilt, the IP was reassigned, or someone is "
                    f"intercepting the connection. Inspect manually or run "
                    f"`fourdollarvpn setup` to provision a new droplet. ({e})"
                ) from e
            except Exception:
                if attempt == SSH_MAX_RETRIES:
                    raise SSHError(
                        f"Could not connect to {self.host} after "
                        f"{SSH_MAX_RETRIES} attempts"
                    )
                console.print("  Waiting for SSH...")
                time.sleep(SSH_RETRY_DELAY)

    def _drain(self, stdout, stderr) -> tuple[str, str]:
        """Drain stdout and stderr concurrently, then wait for exit.

        Reading stdout via recv_exit_status first deadlocks when the remote
        process writes more than the SSH channel window (~2 MiB): it blocks
        on write, never exits, and we hang. Draining on background threads
        keeps the channel window moving so the remote can finish.
        """
        out_buf: list[bytes] = []
        err_buf: list[bytes] = []

        def _pump(stream, buf):
            try:
                for chunk in iter(lambda: stream.read(65536), b""):
                    buf.append(chunk)
            except Exception:
                pass

        t_out = threading.Thread(target=_pump, args=(stdout, out_buf), daemon=True)
        t_err = threading.Thread(target=_pump, args=(stderr, err_buf), daemon=True)
        t_out.start()
        t_err.start()
        exit_code = stdout.channel.recv_exit_status()
        t_out.join()
        t_err.join()
        return (
            b"".join(out_buf).decode(errors="replace").strip(),
            b"".join(err_buf).decode(errors="replace").strip(),
        ), exit_code

    def run(self, command: str, check: bool = True) -> str:
        if not self.client:
            raise SSHError("Not connected")

        _, stdout, stderr = self.client.exec_command(command, timeout=120)
        (out, err), exit_code = self._drain(stdout, stderr)

        if check and exit_code != 0:
            safe_cmd = redact_secrets(command)
            safe_err = redact_secrets(err)
            raise SSHError(
                f"Command failed (exit {exit_code}): {safe_cmd}\n{safe_err}"
            )
        return out

    def run_with_stdin(
        self, command: str, stdin_data: str, check: bool = True
    ) -> str:
        """Run a remote command, piping stdin_data to its stdin.

        Used when we need to pass secret material (PSK, private key) to
        a remote tool without exposing it via the process argv.
        """
        if not self.client:
            raise SSHError("Not connected")

        stdin, stdout, stderr = self.client.exec_command(command, timeout=120)
        try:
            stdin.write(stdin_data)
        finally:
            stdin.channel.shutdown_write()
        (out, err), exit_code = self._drain(stdout, stderr)

        if check and exit_code != 0:
            safe_cmd = redact_secrets(command)
            safe_err = redact_secrets(err)
            raise SSHError(
                f"Command failed (exit {exit_code}): {safe_cmd}\n{safe_err}"
            )
        return out

    def close(self):
        if self.client:
            self.client.close()
            self.client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()
