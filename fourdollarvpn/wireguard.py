from __future__ import annotations

from .crypto import generate_keypair_local, generate_preshared_key
from .ssh import SSHConnection, SSHError

WG_PORT = 51820
WG_INTERFACE = "wg0"
WG_NETWORK = "10.66.66"
WG_SERVER_IP = f"{WG_NETWORK}.1/24"
DNS_SERVERS = "1.1.1.1, 1.0.0.1"


def trigger_background_upgrade(ssh: SSHConnection):
    """Kick off a full `apt upgrade` as a detached systemd transient unit.

    The unit survives our SSH disconnect and runs to completion autonomously.
    Progress can be checked with:
        journalctl -u fourdollarvpn-initial-upgrade -f
    """
    cmd = (
        "systemd-run --unit=fourdollarvpn-initial-upgrade "
        '--description="FourDollarVPN initial system upgrade" '
        "--setenv=DEBIAN_FRONTEND=noninteractive "
        "/bin/bash -c '"
        "apt-get update -qq && "
        'apt-get -y -o Dpkg::Options::="--force-confdef" '
        '-o Dpkg::Options::="--force-confold" upgrade && '
        "apt-get -y autoremove"
        "'"
    )
    ssh.run(cmd)


def wait_for_cloud_init(ssh: SSHConnection):
    """Block until cloud-init finishes — it holds the dpkg lock on fresh
    droplets and would make our apt commands hang silently."""
    ssh.run("cloud-init status --wait 2>/dev/null || true", check=False)


def install_wireguard(ssh: SSHConnection):
    ssh.run("apt-get update -qq")
    ssh.run(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "wireguard chrony needrestart"
    )
    # Configure needrestart to auto-restart services (never prompt), so it
    # doesn't hang noninteractive apt runs (including background upgrades).
    ssh.run(
        "mkdir -p /etc/needrestart/conf.d && "
        "echo \"\\$nrconf{restart} = 'a';\" "
        "> /etc/needrestart/conf.d/99-fourdollarvpn.conf"
    )
    # Ensure accurate time sync (critical for crypto handshakes)
    ssh.run("systemctl enable chrony")
    ssh.run("systemctl restart chrony")


def enable_ip_forwarding(ssh: SSHConnection):
    ssh.run("echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf")
    ssh.run("sysctl -p /etc/sysctl.d/99-wireguard.conf")


def harden_kernel(ssh: SSHConnection):
    """Apply network-layer kernel hardening via sysctl."""
    sysctl_config = """# FourDollarVPN kernel hardening
# Anti-spoofing (strict reverse path filtering)
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# SYN flood protection
net.ipv4.tcp_syncookies=1

# Disable source routing
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0

# Disable IPv6 entirely (droplet is IPv4-only)
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1

# Log suspicious packets
net.ipv4.conf.all.log_martians=1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts=1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses=1
"""
    ssh.run(
        f"cat > /etc/sysctl.d/99-fourdollarvpn-hardening.conf << 'SYSEOF'\n"
        f"{sysctl_config}SYSEOF"
    )
    ssh.run("sysctl -p /etc/sysctl.d/99-fourdollarvpn-hardening.conf")


def generate_server_keypair(ssh: SSHConnection) -> tuple[str, str]:
    """Generate server keypair on the server — private key never leaves.

    The public key is derived by piping the private key to `wg pubkey`
    via stdin (not via `echo`) so the private key never appears in the
    server's process argv / `/proc/*/cmdline`.
    """
    private = ssh.run("wg genkey")
    public = ssh.run_with_stdin("wg pubkey", private)
    return private, public


def configure_server(
    ssh: SSHConnection,
    server_private_key: str,
    client_public_key: str,
    preshared_key: str,
    server_ip: str,
):
    # Detect the main network interface
    interface = ssh.run(
        "ip -o -4 route show to default | awk '{print $5}' | head -1"
    )

    config = f"""[Interface]
Address = {WG_SERVER_IP}
ListenPort = {WG_PORT}
PrivateKey = {server_private_key}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE

[Peer]
PublicKey = {client_public_key}
PresharedKey = {preshared_key}
AllowedIPs = {WG_NETWORK}.2/32
"""
    # Write config with restricted permissions
    ssh.run(f"umask 077 && cat > /etc/wireguard/{WG_INTERFACE}.conf << 'WGEOF'\n{config}WGEOF")
    ssh.run(f"chmod 600 /etc/wireguard/{WG_INTERFACE}.conf")


CLIENT_NAME_RE = r"[A-Za-z0-9_-]{1,32}"


def _re_name_match(line: str) -> str | None:
    """If `line` is a `# fourdollarvpn: name=...` marker, return the name."""
    import re as _re
    m = _re.fullmatch(
        rf"#\s*fourdollarvpn:\s*name=({CLIENT_NAME_RE})", line
    )
    return m.group(1) if m else None


def add_client_and_allocate_ip(
    ssh: SSHConnection,
    client_public_key: str,
    preshared_key: str,
    name: str | None = None,
) -> str:
    """Atomically: pick the next unused client IP, live-add the peer to
    the running interface, and append it to the on-disk config.

    Returns the allocated IP (e.g. "10.66.66.3").

    Guarantees:
    - Holds a server-side flock for the entire read/allocate/write
      sequence, so concurrent `add-client` invocations never collide on
      the same IP.
    - Picks the lowest unused octet in [2, 254] by parsing actual
      `AllowedIPs` values (not peer-block count), so gaps left by
      manually removed peers get reused correctly.
    - Runs `wg set` BEFORE appending to disk. If `wg set` fails, the
      on-disk config is untouched — no orphan peer blocks.
    - PSK is passed in via stdin and written to `/dev/shm` (tmpfs) with
      a 077 umask, so it's never in argv / `/proc/*/cmdline` and gets
      wiped automatically when the file is removed.

    Raises SSHError if no free IP is available or wg set fails.
    """
    # client_public_key is base64 ([A-Za-z0-9+/=]) from a local Curve25519
    # keypair — it can never contain shell metacharacters. Even so, we
    # validate defensively so a future refactor that accepts a
    # user-supplied pubkey can't become an RCE vector.
    import re as _re

    if not _re.fullmatch(r"[A-Za-z0-9+/]{43}=", client_public_key):
        raise SSHError("Invalid client public key format")
    if name is not None and not _re.fullmatch(CLIENT_NAME_RE, name):
        raise SSHError(
            "Invalid client name — use 1-32 chars from [A-Za-z0-9_-]"
        )

    # Safe to embed the name directly: the regex above excludes every
    # shell / WireGuard-conf metacharacter.
    name_comment = f"# fourdollarvpn: name={name}\n" if name else ""

    script = r"""set -e
exec 200>/var/lock/fourdollarvpn-addpeer.lock
flock 200

USED=$(grep -oE 'AllowedIPs[[:space:]]*=[[:space:]]*""" + WG_NETWORK.replace(".", r"\.") + r"""\.[0-9]+' /etc/wireguard/""" + WG_INTERFACE + r""".conf 2>/dev/null | grep -oE '[0-9]+$' | sort -n || true)
NEXT=""
for i in $(seq 2 254); do
    if ! echo "$USED" | grep -qx "$i"; then NEXT=$i; break; fi
done
if [ -z "$NEXT" ]; then
    echo "QVPN_NO_FREE_IP" >&2
    exit 10
fi
IP=""" + WG_NETWORK + r""".$NEXT

umask 077
PSK_FILE=$(mktemp -p /dev/shm fourdollarvpn-psk-XXXXXX)
# PSK arrives on stdin — never in argv or env
cat > "$PSK_FILE"

# Live-add the peer FIRST. If this fails, nothing persists.
if ! wg set """ + WG_INTERFACE + r""" peer '""" + client_public_key + r"""' \
        preshared-key "$PSK_FILE" allowed-ips "$IP/32"; then
    rm -f "$PSK_FILE"
    echo "QVPN_WG_SET_FAILED" >&2
    exit 11
fi

# wg set succeeded — now commit to disk
PSK_VAL=$(cat "$PSK_FILE")
cat >> /etc/wireguard/""" + WG_INTERFACE + r""".conf <<EOP

""" + name_comment + r"""[Peer]
PublicKey = """ + client_public_key + r"""
PresharedKey = $PSK_VAL
AllowedIPs = $IP/32
EOP

shred -u "$PSK_FILE" 2>/dev/null || rm -f "$PSK_FILE"

echo "$IP"
"""
    try:
        result = ssh.run_with_stdin(script, preshared_key)
    except SSHError as e:
        # Match on the distinctive stderr markers + exit codes. We avoid
        # plain tokens like "no-free-ip" because the full script body
        # appears in the error message; anything that could match the
        # script's own text produces false classifications.
        msg = str(e)
        if "QVPN_NO_FREE_IP" in msg and "(exit 10)" in msg:
            raise SSHError(
                "No free client IP available — 253 clients already "
                "configured on this server."
            ) from e
        if "QVPN_WG_SET_FAILED" in msg and "(exit 11)" in msg:
            raise SSHError(
                "Failed to live-add WireGuard peer (wg set). The server "
                "config was not modified. Try `fourdollarvpn check` to verify "
                "the interface is up."
            ) from e
        raise

    ip = result.strip().splitlines()[-1]
    if not _re.fullmatch(rf"{_re.escape(WG_NETWORK)}\.\d+", ip):
        raise SSHError(f"Unexpected allocator output: {ip!r}")
    return ip


def list_peers(ssh: SSHConnection) -> list[dict]:
    """Return the current list of WireGuard peers on the server.

    Each entry is a dict with: pubkey, ip, name, handshake (unix
    timestamp, 0 if never), endpoint, rx, tx. `name` is "" for peers
    added without --name (or by hand outside FourDollarVPN). Parses
    `wg show <iface> dump` for live data; joins with name comments
    harvested from the on-disk config (`# fourdollarvpn: name=X` lines
    preceding a [Peer] block).
    """
    # Harvest pubkey -> name mappings from the conf file. `wg show dump`
    # doesn't know about comments, so names only live on disk.
    conf = ssh.run(
        f"cat /etc/wireguard/{WG_INTERFACE}.conf", check=False
    )
    names: dict[str, str] = {}
    pending_name: str | None = None
    for raw in conf.splitlines():
        line = raw.strip()
        m = _re_name_match(line)
        if m:
            pending_name = m
            continue
        if line.startswith("PublicKey"):
            pub = line.split("=", 1)[1].strip()
            # AllowedIPs / PresharedKey also match startswith("P"), but
            # PublicKey is always the first field in a peer block emitted
            # by both `wg` and our add-client script.
            if pending_name and pub:
                names[pub] = pending_name
            pending_name = None
        elif line.startswith("[") and not line.startswith("[Peer]"):
            # [Interface] or similar — drop any pending name
            pending_name = None

    out = ssh.run(f"wg show {WG_INTERFACE} dump | tail -n +2", check=False)
    peers = []
    for line in out.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        pub, _psk, endpoint, allowed_ips, handshake, rx, tx, _keep = fields[:8]
        # AllowedIPs for a client is always "10.66.66.N/32"
        ip = ""
        if allowed_ips and allowed_ips != "(none)":
            ip = allowed_ips.split(",")[0].split("/")[0].strip()
        peers.append(
            {
                "pubkey": pub,
                "ip": ip,
                "name": names.get(pub, ""),
                "endpoint": "" if endpoint in ("(none)", "") else endpoint,
                "handshake": int(handshake) if handshake.isdigit() else 0,
                "rx": int(rx) if rx.isdigit() else 0,
                "tx": int(tx) if tx.isdigit() else 0,
            }
        )
    # Sort by IP numerically so output is deterministic
    def _ip_key(p):
        try:
            return int(p["ip"].split(".")[-1])
        except (ValueError, IndexError):
            return 999
    peers.sort(key=_ip_key)
    return peers


def remove_peer(ssh: SSHConnection, pubkey: str) -> None:
    """Atomically remove a peer from the running interface AND the
    on-disk config. Holds the same flock as add_client_and_allocate_ip
    so concurrent adds/removes can't interleave.

    Raises SSHError if the peer isn't found in the config.
    """
    import re as _re

    if not _re.fullmatch(r"[A-Za-z0-9+/]{43}=", pubkey):
        raise SSHError("Invalid public key format")

    # Escape the pubkey for safe embedding in awk -v (only `\` and `"`
    # are meta within double-quoted awk strings; base64 has neither).
    script = r"""set -e
exec 200>/var/lock/fourdollarvpn-addpeer.lock
flock 200

CONF=/etc/wireguard/""" + WG_INTERFACE + r""".conf
if ! grep -qE "^PublicKey[[:space:]]*=[[:space:]]*""" + _re.escape(pubkey) + r"""[[:space:]]*$" "$CONF"; then
    echo "not-found" >&2
    exit 3
fi

# Live-remove from the running interface (ignore errors — maybe not loaded)
wg set """ + WG_INTERFACE + r""" peer '""" + pubkey + r"""' remove 2>/dev/null || true

# Rewrite the config without the matching [Peer] block. awk streams through
# one section at a time; if the buffered section contains a PublicKey line
# that equals our target, we drop it, otherwise we emit it verbatim.
umask 077
awk -v pub='""" + pubkey + r"""' '
  BEGIN { buf=""; target=0 }
  /^\[/ {
    if (buf != "" && !target) printf "%s", buf
    buf = $0 "\n"
    target = 0
    next
  }
  {
    buf = buf $0 "\n"
    if ($1 == "PublicKey" && $2 == "=" && $3 == pub) target = 1
  }
  END {
    if (buf != "" && !target) printf "%s", buf
  }
' "$CONF" > "$CONF.tmp"
chmod 600 "$CONF.tmp"
mv "$CONF.tmp" "$CONF"
echo "removed"
"""
    try:
        ssh.run(script)
    except SSHError as e:
        if "not-found" in str(e):
            raise SSHError(
                f"No peer with public key {pubkey[:8]}... found on the server."
            ) from e
        raise


def start_wireguard(ssh: SSHConnection):
    ssh.run(f"systemctl enable wg-quick@{WG_INTERFACE}")
    ssh.run(f"systemctl start wg-quick@{WG_INTERFACE}")


def generate_client_config(
    client_private_key: str,
    server_public_key: str,
    preshared_key: str,
    server_ip: str,
    client_address: str,
) -> str:
    return f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_address}/24
DNS = {DNS_SERVERS}

[Peer]
PublicKey = {server_public_key}
PresharedKey = {preshared_key}
Endpoint = {server_ip}:{WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""


def harden_ssh(ssh: SSHConnection):
    sshd_hardening = [
        ("PermitRootLogin", "prohibit-password"),
        ("PasswordAuthentication", "no"),
        ("PermitEmptyPasswords", "no"),
        ("ChallengeResponseAuthentication", "no"),
        ("KbdInteractiveAuthentication", "no"),
        ("UsePAM", "yes"),
        ("X11Forwarding", "no"),
        ("AllowTcpForwarding", "no"),
        ("AllowAgentForwarding", "no"),
        ("MaxAuthTries", "3"),
        ("LoginGraceTime", "30"),
        ("ClientAliveInterval", "300"),
        ("ClientAliveCountMax", "2"),
    ]
    for key, value in sshd_hardening:
        # Remove any existing setting, then append the hardened value
        ssh.run(f"sed -i '/^#\\?{key}/d' /etc/ssh/sshd_config")
        ssh.run(f"echo '{key} {value}' >> /etc/ssh/sshd_config")
    # Ubuntu uses ssh.service; RHEL/CentOS uses sshd.service
    ssh.run("systemctl restart ssh 2>/dev/null || systemctl restart sshd")


def install_fail2ban(ssh: SSHConnection):
    ssh.run("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban")
    jail_config = """[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
"""
    ssh.run(
        f"cat > /etc/fail2ban/jail.local << 'F2BEOF'\n{jail_config}F2BEOF"
    )
    ssh.run("systemctl enable fail2ban")
    ssh.run("systemctl restart fail2ban")


def configure_firewall(ssh: SSHConnection):
    ssh.run("apt-get install -y -qq ufw")
    # UFW's default FORWARD policy is DROP — must be ACCEPT for VPN routing
    ssh.run(
        "sed -i 's/^DEFAULT_FORWARD_POLICY=.*/"
        "DEFAULT_FORWARD_POLICY=\"ACCEPT\"/' /etc/default/ufw"
    )
    ssh.run("ufw default deny incoming")
    ssh.run("ufw default allow outgoing")
    ssh.run("ufw default allow routed")
    # `limit` adds UFW's built-in SSH rate-limiter on top of fail2ban —
    # 6 connection attempts / 30 seconds = temporary ban.
    ssh.run("ufw limit 22/tcp")
    ssh.run(f"ufw allow {WG_PORT}/udp")
    ssh.run("echo 'y' | ufw enable")
    # Reload to apply the forward policy change
    ssh.run("ufw reload")


def lock_ssh(ssh: SSHConnection):
    """Block inbound SSH at the firewall.

    `configure_firewall` adds the SSH rule as `ufw limit 22/tcp` (rate-limit
    on top of fail2ban), so removing it requires matching that exact action —
    `ufw delete allow 22/tcp` silently no-ops because no 'allow' rule was
    ever installed. Previously this meant `--lock` advertised a firewall
    block but actually did nothing.

    Belt-and-braces: after deleting the limit rule, add an explicit
    `ufw deny 22/tcp`. The default policy is already `deny incoming`, so
    the explicit deny is redundant in the happy path — but it means that
    if anything (e.g., a future code change, a user editing `/etc/default/ufw`)
    flips the default to allow, port 22 stays blocked regardless.
    """
    ssh.run("ufw delete limit 22/tcp")
    ssh.run("ufw deny 22/tcp")
    ssh.run("ufw reload")


def enable_auto_updates(ssh: SSHConnection):
    ssh.run(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "unattended-upgrades"
    )
    auto_upgrades_conf = (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
    )
    ssh.run(
        f"cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUEOF'\n"
        f"{auto_upgrades_conf}AUEOF"
    )

    # Reboot automatically at 04:00 UTC only when an update requires
    # it (i.e. /var/run/reboot-required exists). Typically fires once
    # every week or two for kernel / glibc / systemd updates; never
    # otherwise. 04:00 UTC was chosen as a globally-quiet window
    # (≈ 9pm PST / midnight EST / 5am London / noon JST). Written to
    # a separate file so we don't clobber the distro-shipped
    # /etc/apt/apt.conf.d/50unattended-upgrades.
    auto_reboot_conf = (
        'Unattended-Upgrade::Automatic-Reboot "true";\n'
        'Unattended-Upgrade::Automatic-Reboot-Time "04:00";\n'
    )
    ssh.run(
        f"cat > /etc/apt/apt.conf.d/51fourdollarvpn-auto-reboot << 'ARBEOF'\n"
        f"{auto_reboot_conf}ARBEOF"
    )


def collect_security_status(ssh: SSHConnection) -> dict:
    """Collect verification data from the server for end-of-setup display."""
    status = {}
    status["ufw"] = ssh.run("ufw status | head -3", check=False)
    status["fail2ban"] = ssh.run(
        "systemctl is-active fail2ban", check=False
    )
    status["wireguard"] = ssh.run(
        f"systemctl is-active wg-quick@{WG_INTERFACE}", check=False
    )
    status["chrony"] = ssh.run("systemctl is-active chrony", check=False)
    # unattended-upgrades is oneshot; check the timer + config file instead
    status["auto_updates"] = ssh.run(
        "systemctl is-active apt-daily-upgrade.timer", check=False
    )
    status["listening"] = ssh.run(
        "ss -tuln | awk 'NR>1 {print $5}' | sort -u", check=False
    )
    return status


def get_setup_steps(
    ssh: SSHConnection, server_ip: str, lock: bool = False
) -> list[tuple[str, callable]]:
    """
    Returns a list of (description, callable) steps for the caller to execute
    with its own progress display. The callable has no args.

    Populates `state` as it runs so the final client config can be built
    after all steps complete.
    """
    state = {}

    def _wait_cloud_init():
        wait_for_cloud_init(ssh)

    def _install():
        install_wireguard(ssh)

    def _bg_upgrade():
        trigger_background_upgrade(ssh)

    def _enable_forwarding():
        enable_ip_forwarding(ssh)

    def _harden_kernel():
        harden_kernel(ssh)

    def _gen_server_keys():
        state["server_priv"], state["server_pub"] = generate_server_keypair(ssh)

    def _gen_client_keys():
        # Local generation — private key never touches the server
        state["client_priv"], state["client_pub"] = generate_keypair_local()
        state["psk"] = generate_preshared_key()

    def _configure_server():
        configure_server(
            ssh, state["server_priv"], state["client_pub"],
            state["psk"], server_ip,
        )

    def _start_wg():
        start_wireguard(ssh)

    def _firewall():
        configure_firewall(ssh)

    def _harden_ssh():
        harden_ssh(ssh)

    def _fail2ban():
        install_fail2ban(ssh)

    def _auto_updates():
        enable_auto_updates(ssh)

    def _collect_status():
        state["status"] = collect_security_status(ssh)
        state["client_config"] = generate_client_config(
            state["client_priv"], state["server_pub"], state["psk"],
            server_ip, f"{WG_NETWORK}.2",
        )

    def _lock_ssh():
        lock_ssh(ssh)

    # Order matters: `harden_ssh` restarts sshd, which can sever our
    # paramiko channel on slower droplets. Run all the other provisioning
    # steps first so a broken SSH restart can't take down the rest of the
    # setup, and status collection (which happens over the same channel)
    # runs BEFORE we touch sshd.
    steps = [
        ("Waiting for cloud-init to finish", _wait_cloud_init),
        ("Installing WireGuard, chrony, needrestart (~30s)", _install),
        ("Enabling IP forwarding", _enable_forwarding),
        ("Hardening kernel (sysctl)", _harden_kernel),
        ("Generating server keypair", _gen_server_keys),
        ("Generating client keypair + PSK (local)", _gen_client_keys),
        ("Writing WireGuard config", _configure_server),
        ("Starting WireGuard", _start_wg),
        ("Configuring firewall (UFW)", _firewall),
        ("Installing fail2ban", _fail2ban),
        ("Enabling automatic security updates", _auto_updates),
        ("Collecting verification status", _collect_status),
        ("Triggering background full system upgrade", _bg_upgrade),
        ("Hardening SSH (restart)", _harden_ssh),
    ]
    if lock:
        steps.append(("Locking SSH (firewall)", _lock_ssh))

    return steps, state
