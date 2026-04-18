from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import time
import webbrowser

import qrcode
from qrcode.image.svg import SvgPathImage
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from . import __version__
from .config import config_path, load_config, save_config
from .provider import DigitalOcean, DigitalOceanError
from .ssh import (
    KNOWN_HOSTS_PATH,
    SERVER_KEYS_DIR,
    SSHConnection,
    SSHError,
    _droplet_key_path,
    forget_droplet_key,
    load_droplet_key,
    redact_secrets,
    save_droplet_key,
)
from .crypto import generate_keypair_local, generate_preshared_key
from .wireguard import (
    WG_NETWORK,
    add_client_and_allocate_ip,
    generate_client_config,
    get_setup_steps,
    list_peers,
    remove_peer,
)

console = Console()


def _write_secret_file(path: str, content: str) -> None:
    """Write text to `path` with 0600 perms. Refuses to follow a symlink
    (O_NOFOLLOW where supported), overwrites an existing regular file.

    We previously used O_EXCL to refuse any existing file — that protected
    against a particular symlink race, but in practice it just broke the
    common case of re-running `setup` after a destroyed-and-recreated
    droplet got assigned a recycled IP (same filename as before). The
    O_NOFOLLOW check covers the main concern (malicious symlink planted
    by another local user) without tripping on our own leftover files.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    # Force mode in case umask or pre-existing file perms overrode us.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _save_qr_svg(content: str, svg_path: str) -> None:
    """Save a QR-SVG at `svg_path` with 0600 perms and no readable window."""
    old_umask = os.umask(0o077)
    try:
        qrcode.make(content, image_factory=SvgPathImage).save(svg_path)
    finally:
        os.umask(old_umask)
    # Belt-and-suspenders: ensure mode is 0600 even if filesystem ignored umask.
    try:
        os.chmod(svg_path, 0o600)
    except OSError:
        pass


_ENDPOINT_RE = re.compile(
    r"^\s*Endpoint\s*=\s*([0-9.]+)\s*:\s*\d+\s*$",
    re.MULTILINE,
)


def _read_endpoint_ip(conf_path: str) -> str | None:
    """Return the server IP from a FourDollarVPN client .conf, or None if
    the file can't be read / parsed. Uses the `Endpoint = IP:PORT`
    line rather than the filename, so renamed files still classify
    correctly.
    """
    try:
        with open(conf_path, "r", encoding="utf-8", errors="replace") as f:
            m = _ENDPOINT_RE.search(f.read())
    except OSError:
        return None
    return m.group(1) if m else None


def _offer_stale_config_cleanup(
    directories: list[str],
    live_server_ips: set[str],
) -> None:
    """Find FourDollarVPN client configs whose Endpoint is NOT in
    `live_server_ips`, print them, and offer to delete each .conf +
    its sibling .svg.

    `live_server_ips` must be the live set from DO — we only classify
    a file as 'stale' if we're certain its server no longer exists.
    """
    seen: set[str] = set()
    stale: list[tuple[str, str]] = []  # (path, endpoint_ip)
    for d in directories:
        if not d:
            continue
        try:
            # All FourDollarVPN-generated configs start with 'fdvpn-';
            # the exact format varies between setup and add-client, but
            # classification uses the Endpoint line inside the file, not
            # the filename.
            matches = glob.glob(os.path.join(d, "fdvpn-*.conf"))
        except OSError:
            continue
        for path in matches:
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            ip = _read_endpoint_ip(path)
            if ip and ip not in live_server_ips:
                stale.append((path, ip))

    if not stale:
        return

    console.print(
        f"\n[yellow]Found {len(stale)} old FourDollarVPN client config file(s) "
        f"from droplets that no longer exist:[/yellow]"
    )
    for path, ip in stale:
        console.print(f"  [dim]{path}[/dim]  (was {ip})")
    try:
        answer = console.input(
            r"Delete these (and their matching .svg QR codes)? \[y/n, default: y]: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"  # Treat interrupt as "don't delete" — safety over convenience
    if answer in ("n", "no"):
        console.print("[dim]Left them in place.[/dim]")
        return

    removed = 0
    for path, _ in stale:
        for p in (path, path[:-5] + ".svg"):
            if os.path.exists(p):
                try:
                    os.remove(p)
                    removed += 1
                except OSError as e:
                    console.print(f"  [red]Couldn't remove {p}: {e}[/red]")
    console.print(f"[green]Removed {removed} file(s).[/green]")


def _save_with_fallback(
    path: str,
    writer,
    *,
    is_explicit: bool,
) -> str:
    """Try writing to `path`. If that fails with PermissionError / OSError
    AND the caller didn't ask for a specific location (`is_explicit=False`),
    fall back to the same filename inside the user's home directory.

    Returns the path that was actually written.

    Exists because Windows routinely blocks writes into the cwd when the
    binary is double-clicked from OneDrive-synced folders, Controlled
    Folder Access-protected locations (Desktop/Documents by default on
    some setups), or Program Files. Home directory is almost always
    writable.

    `writer` is `_write_secret_file` or `_save_qr_svg` — a callable
    taking `(content-ish, path)`. Implemented via the closure below
    so each caller keeps its own content reference.
    """
    try:
        writer(path)
        return path
    except (PermissionError, OSError) as first_err:
        if is_explicit:
            # User asked for this exact path — respect it, don't silently
            # save somewhere they didn't expect.
            raise
        home_path = os.path.join(
            os.path.expanduser("~"), os.path.basename(path)
        )
        if os.path.abspath(home_path) == os.path.abspath(path):
            raise  # already at home, nowhere else to try
        try:
            writer(home_path)
        except OSError:
            raise first_err  # original error is more actionable
        console.print(
            f"[yellow]Note:[/yellow] couldn't write to "
            f"[bold]{path}[/bold] ({type(first_err).__name__}), "
            f"saved to [bold]{home_path}[/bold] instead."
        )
        return home_path


def _print_error(prefix: str, err: Exception) -> None:
    """Print a user-facing error, scrubbing any embedded secrets."""
    console.print(f"[red]{prefix}{redact_secrets(str(err))}[/red]")


def get_token(args) -> str:
    """Resolve the DO API token. Precedence:

    1. --token flag
    2. DO_API_TOKEN env var
    3. saved config (fourdollarvpn init)

    Fails fast with an actionable message if none of the above yield a token.
    """
    token = getattr(args, "token", None) or os.environ.get("DO_API_TOKEN")
    if not token:
        cfg = load_config()
        token = cfg.get("token")
    if not token:
        console.print(
            "[red]No API token found.[/red]\n"
            "Run [bold]fourdollarvpn init[/bold] to save one, or pass "
            "[bold]--token[/bold] / set [bold]DO_API_TOKEN[/bold]."
        )
        sys.exit(1)
    return token


def select_region(do: DigitalOcean, region_slug: str | None) -> str:
    if region_slug:
        return region_slug

    regions = do.list_regions()
    if not regions:
        console.print("[red]No available regions found.[/red]")
        sys.exit(1)

    table = Table(title="Available Regions")
    table.add_column("#", style="dim")
    table.add_column("Slug")
    table.add_column("Name")

    for i, r in enumerate(regions, 1):
        table.add_row(str(i), r["slug"], r["name"])

    console.print(table)
    console.print()

    # Default to sfo2 if the account has it; otherwise the first listed
    # region. sfo2 is a reasonable default for US users — low latency on
    # the West Coast, good peering, well-staffed DO region.
    default_slug = "sfo2" if any(r["slug"] == "sfo2" for r in regions) else regions[0]["slug"]

    while True:
        choice = console.input(
            rf"Select a region (number or slug) \[default: {default_slug}]: "
        ).strip()
        if not choice:
            return default_slug
        # Try as number
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(regions):
                return regions[idx]["slug"]
        except ValueError:
            pass
        # Try as slug
        for r in regions:
            if r["slug"] == choice:
                return choice
        console.print("[red]Invalid selection, try again.[/red]")


def open_in_browser(path: str) -> bool:
    """Open a local file in the user's default browser. Returns True on success."""
    try:
        abs_path = os.path.abspath(path)
        return webbrowser.open(f"file://{abs_path}")
    except Exception:
        return False


def print_qr_code(config: str):
    """Print a square QR code of the client config using Unicode half-blocks.

    Each character renders a 1-module-wide × 2-module-tall cell — this matches
    the aspect ratio of terminal characters (roughly 1:2), so the resulting
    QR comes out visually square.
    """
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=1,
    )
    qr.add_data(config)
    qr.make(fit=True)
    matrix = qr.get_matrix()

    # Pad to an even number of rows so every top/bottom pair is complete
    if len(matrix) % 2:
        matrix.append([False] * len(matrix[0]))

    # Half-block chars indexed by (top, bottom) packed as a 2-bit int.
    # invert=True: dark QR modules become spaces (readable on dark terminals).
    blocks = " ▄▀█"

    lines = []
    for y in range(0, len(matrix), 2):
        line = []
        for x in range(len(matrix[0])):
            top = not matrix[y][x]
            bot = not matrix[y + 1][x]
            line.append(blocks[(top << 1) | bot])
        lines.append("".join(line))
    console.print("\n".join(lines))


def print_security_checklist(status: dict):
    """Print a pass/fail security checklist from server status data."""
    def check(name: str, condition: bool, detail: str = ""):
        icon = "[green]✓[/green]" if condition else "[red]✗[/red]"
        line = f"  {icon} {name}"
        if detail:
            line += f"  [dim]{detail}[/dim]"
        console.print(line)

    console.print()
    console.print("[bold]Security verification:[/bold]")
    ufw_text = status.get("ufw", "").lower()
    ufw_active = any(
        line.strip().startswith("status: active")
        for line in ufw_text.splitlines()
    )
    check(
        "Firewall (UFW)",
        ufw_active,
        "deny incoming by default",
    )
    check(
        "fail2ban (SSH rate limiting)",
        status.get("fail2ban") == "active",
        "5 fails = 1hr ban",
    )
    check(
        "WireGuard running",
        status.get("wireguard") == "active",
    )
    check(
        "Time sync (chrony)",
        status.get("chrony") == "active",
        "required for crypto",
    )
    check(
        "Automatic security updates",
        status.get("auto_updates") == "active",
    )
    listening = status.get("listening", "")
    unexpected = []
    for line in listening.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        # Allow SSH (:22), WireGuard (:51820), and loopback-only listeners.
        if ":22" in stripped or ":51820" in stripped:
            continue
        if "127.0.0.1:" in stripped or "[::1]:" in stripped:
            continue
        unexpected.append(stripped)
    check(
        "Only SSH + WireGuard ports listening",
        not unexpected,
        f"unexpected: {unexpected[0]}" if unexpected else "",
    )


def cmd_init(args):
    """Save a DigitalOcean API token (and verify it) so subsequent
    commands don't need --token or DO_API_TOKEN exported."""
    cfg = load_config()
    existing = cfg.get("token")

    prompt = "DigitalOcean API token"
    if existing:
        prompt += f" (press Enter to keep ending ...{existing[-4:]})"
    prompt += ": "

    try:
        token = console.input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(1)

    if not token and existing:
        token = existing
    if not token:
        console.print("[red]No token entered — nothing saved.[/red]")
        sys.exit(1)

    # Verify against DO before persisting so we don't save a bad token
    do = DigitalOcean(token)
    try:
        with console.status("Verifying token with DigitalOcean..."):
            do.verify_token()
    except DigitalOceanError as e:
        _print_error("Token rejected: ", e)
        sys.exit(1)

    cfg["token"] = token
    path = save_config(cfg)

    console.print(
        f"[green]✓ Token verified and saved to {path}[/green]\n"
        f"You can now run [bold]fourdollarvpn setup[/bold] (or any other "
        f"command) without passing --token.\n\n"
        f"[dim]Revoke it later at "
        f"https://cloud.digitalocean.com/account/api/tokens[/dim]"
    )


def cmd_setup(args):
    token = get_token(args)
    do = DigitalOcean(token)

    console.print(
        Panel(
            "[bold]FourDollarVPN Setup[/bold]\n"
            "by [bold cyan]SkyzFallin[/bold cyan] · "
            "[link=https://github.com/SkyzFallin/FourDollarVPN]"
            "github.com/SkyzFallin/FourDollarVPN[/link]",
            style="bold blue",
        )
    )

    # Step 1: Verify token
    with console.status("Verifying API token..."):
        try:
            do.verify_token()
        except DigitalOceanError as e:
            _print_error("", e)
            sys.exit(1)
    console.print("[green]  Token verified.[/green]")

    # Offer to clean up stale client configs before we create yet more
    # files. Scans cwd + home; prompts only if there's at least one
    # config pointing at a droplet that no longer exists.
    try:
        live_ips = {
            d["ip"] for d in do.list_fourdollarvpn_droplets() if d.get("ip")
        }
        _offer_stale_config_cleanup(
            [os.getcwd(), os.path.expanduser("~")], live_ips
        )
    except DigitalOceanError:
        pass

    # Step 1b: Replace any existing FourDollarVPN droplets. The common-sense
    # default for users hitting `setup` when they already have one is
    # "rebuild it" — not "add a second one" (which was the old default
    # and surprised every reviewer). With -y we just do it; without -y
    # we confirm once.
    with console.status("Checking for existing FourDollarVPN droplets..."):
        existing = do.list_fourdollarvpn_droplets()
    if existing:
        table = Table(
            title="[yellow]Existing FourDollarVPN droplets found[/yellow]",
            title_justify="left",
        )
        table.add_column("Name")
        table.add_column("IP")
        table.add_column("Region")
        table.add_column("Status")
        for d in existing:
            table.add_row(
                d["name"], d["ip"] or "N/A", d["region"], d["status"]
            )
        console.print(table)

        if not args.yes:
            console.print(
                "\n[yellow]Continuing will destroy the droplet(s) above "
                "and create a new one.[/yellow]"
            )
            try:
                answer = console.input(
                    r"Proceed? \[y/n, default: y]: "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"
            if answer in ("n", "no"):
                console.print("Cancelled.")
                sys.exit(0)

        for d in existing:
            with console.status(f"Destroying {d['name']}..."):
                try:
                    do.destroy_droplet(d["id"])
                except DigitalOceanError as e:
                    _print_error(f"Failed to destroy {d['name']}: ", e)
                    sys.exit(1)
            forget_droplet_key(d["id"], d.get("ip"))
            console.print(
                f"[green]  ✓ Destroyed {d['name']} ({d['ip']})[/green]"
            )

    # Step 2: Select region
    region = select_region(do, args.region)
    console.print(f"[green]  Region: {region}[/green]")

    # Step 3: Generate temporary SSH key
    with console.status("Generating temporary SSH keypair..."):
        ssh_key, ssh_key_pem = do.generate_ssh_keypair()
    console.print("[green]  SSH keypair generated.[/green]")

    ssh_key_id = None
    droplet_id = None

    try:
        # Step 4: Upload SSH key
        with console.status("Uploading SSH key to DigitalOcean..."):
            key_name = f"fourdollarvpn-{int(time.time())}"
            ssh_key_id = do.upload_ssh_key(ssh_key, key_name)
        console.print("[green]  SSH key uploaded.[/green]")

        # Step 5: Create droplet
        droplet_name = f"fourdollarvpn-{int(time.time())}"
        with console.status(f"Creating droplet '{droplet_name}'..."):
            droplet = do.create_droplet(droplet_name, region, ssh_key_id)
            droplet_id = droplet["id"]
        console.print(f"[green]  Droplet created (ID: {droplet_id}).[/green]")

        # Step 6: Wait for droplet
        with console.status("Waiting for droplet to be ready..."):
            server_ip = do.wait_for_droplet(droplet_id)
        console.print(f"[green]  Droplet active at {server_ip}[/green]")

        # Step 7: SSH in and set up WireGuard.
        # fresh=True: clear any stale known_hosts entry for this IP
        # (DO recycles IPs, and a previous destroyed droplet may have
        # left a now-wrong key pinned).
        console.print("[bold]Setting up WireGuard...[/bold]")
        with SSHConnection(server_ip, ssh_key, fresh=True) as ssh:
            # Persist the key so future `check` / `add-client` /
            # `list-clients` / `remove-client` invocations can SSH in.
            # DigitalOcean only copies SSH keys into a droplet's
            # authorized_keys at create-time; adding new keys to the
            # account later is useless. So this key file is the only
            # way to regain management access after setup finishes.
            save_droplet_key(droplet_id, ssh_key_pem)
            steps, state = get_setup_steps(ssh, server_ip, lock=args.lock)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("•"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task(
                    steps[0][0], total=len(steps)
                )
                for i, (description, step_fn) in enumerate(steps):
                    progress.update(task, description=description)
                    step_fn()
                    progress.advance(task)
                progress.update(task, description="[green]Setup complete[/green]")
            client_config = state["client_config"]
            security_status = state["status"]

        # Step 8: Save client config (0600, refuse to follow symlinks).
        # If cwd isn't writable (Windows CFA / OneDrive / Program Files),
        # fall back to the user's home directory.
        stamp = time.strftime("%H%M")
        # Setup's first client is always allocated WG_NETWORK.2. Use the
        # VPN IP (not the server's public IP) in the filename so this
        # config looks consistent with the ones add-client produces
        # later — all of them identify the client by its 10.66.66.x
        # address.
        first_client_ip = f"{WG_NETWORK}.2"
        default_conf = (
            f"fdvpn-{first_client_ip.replace('.', '-')}-{stamp}.conf"
        )
        config_path = _save_with_fallback(
            args.output or default_conf,
            lambda p: _write_secret_file(p, client_config),
            is_explicit=bool(args.output),
        )

        # Save QR code as SVG for easy viewing in any browser/image viewer
        default_svg = config_path.replace(".conf", ".svg")
        if default_svg == config_path:
            default_svg = config_path + ".svg"
        svg_path = _save_with_fallback(
            default_svg,
            lambda p: _save_qr_svg(client_config, p),
            is_explicit=False,
        )

        # Security checklist
        print_security_checklist(security_status)

        # Optionally open the QR SVG in the default browser
        if args.open_qr:
            open_in_browser(svg_path)

        # Clickable file:// links in terminals that support OSC 8 hyperlinks
        svg_abs = os.path.abspath(svg_path)
        svg_link = f"[link=file://{svg_abs}]{svg_path}[/link]"
        conf_abs = os.path.abspath(config_path)
        conf_link = f"[link=file://{conf_abs}]{config_path}[/link]"

        # Success panel FIRST so it stays visible after QR is printed below
        console.print(
            Panel(
                f"[bold green]VPN is ready![/bold green]\n\n"
                f"Server IP: {server_ip}\n"
                f"Config file: [bold]{conf_link}[/bold]\n"
                f"QR code (SVG): [bold]{svg_link}[/bold]\n\n"
                f"[bold]Next steps:[/bold]\n"
                f"1. Install WireGuard on your device:\n"
                f"   - Windows/Mac/Linux: https://www.wireguard.com/install/\n"
                f"   - iOS/Android: Search 'WireGuard' in your app store\n"
                f"2. Import the config:\n"
                f"   - Desktop: import [bold]{conf_link}[/bold]\n"
                f"   - Mobile: click [bold]{svg_link}[/bold] to open it in\n"
                f"     your browser and scan with the WireGuard app\n"
                f"     (or use the terminal QR code below, or\n"
                f"     re-run with --open-qr to auto-open)\n"
                f"3. Activate the tunnel\n"
                f"4. Enable the kill switch in WireGuard settings\n\n"
                f"[bold]Note:[/bold] A full system upgrade is running in the\n"
                f"background on the server (~2-5 min). Your VPN works fine\n"
                f"during and after; no action needed.\n\n"
                f"[bold]Security tip:[/bold] Revoke your API token now at\n"
                f"https://cloud.digitalocean.com/account/api/tokens\n"
                f"Your VPN will keep running without it.\n\n"
                f"Monthly cost: ~$4 on DigitalOcean (s-1vcpu-512mb-10gb)\n"
                f"To tear down: fourdollarvpn destroy\n\n"
                f"FourDollarVPN by [bold cyan]SkyzFallin[/bold cyan] · "
                f"[link=https://github.com/SkyzFallin/FourDollarVPN]"
                f"github.com/SkyzFallin/FourDollarVPN[/link]",
                title="FourDollarVPN",
                style="green",
            )
        )

        # QR last so it's at the bottom of terminal output — no scrolling up
        console.print()
        console.print("[bold]Scan with WireGuard mobile app:[/bold]")
        print_qr_code(client_config)

    except (DigitalOceanError, SSHError) as e:
        _print_error("\nSetup failed: ", e)
        if droplet_id:
            console.print("[yellow]Cleaning up droplet...[/yellow]")
            try:
                do.destroy_droplet(droplet_id)
                console.print("[yellow]Droplet destroyed.[/yellow]")
            except DigitalOceanError:
                console.print(
                    f"[red]Could not auto-destroy droplet {droplet_id}. "
                    f"Delete it manually in the DigitalOcean dashboard.[/red]"
                )
        sys.exit(1)
    except BaseException as e:
        # Ctrl-C, OSError, requests.Timeout, or any other unexpected
        # exception — we MUST destroy the droplet before propagating
        # or the user keeps paying for an orphaned server.
        if isinstance(e, KeyboardInterrupt):
            reason = "Interrupted by user (Ctrl-C)"
        else:
            reason = f"{type(e).__name__}: {redact_secrets(str(e))}"
        console.print(f"\n[red]Setup failed: {reason}[/red]")
        if droplet_id:
            console.print(
                "[yellow]Cleaning up droplet to avoid runaway billing...[/yellow]"
            )
            try:
                do.destroy_droplet(droplet_id)
                console.print("[yellow]Droplet destroyed.[/yellow]")
            except DigitalOceanError:
                console.print(
                    f"[red]Could not auto-destroy droplet {droplet_id}. "
                    f"Delete it manually in the DigitalOcean dashboard.[/red]"
                )
        raise
    finally:
        # Always clean up the temporary SSH key from DO
        if ssh_key_id:
            do.delete_ssh_key(ssh_key_id)


def cmd_status(args):
    token = get_token(args)
    do = DigitalOcean(token)

    with console.status("Fetching FourDollarVPN droplets..."):
        droplets = do.list_fourdollarvpn_droplets()

    if not droplets:
        console.print("No FourDollarVPN droplets found.")
        return

    table = Table(title="FourDollarVPN Droplets")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Region")
    table.add_column("Status")
    table.add_column("Created")

    for d in droplets:
        table.add_row(
            str(d["id"]),
            d["name"],
            d["ip"] or "N/A",
            d["region"],
            d["status"],
            d["created_at"],
        )

    console.print(table)


def cmd_uninstall(args):
    """Remove FourDollarVPN's saved token and known_hosts from this machine.

    Does NOT touch running droplets — run `fourdollarvpn destroy` first if
    you want to stop billing. The .exe / script itself isn't deleted
    either; remove that manually when you're done.
    """
    cfg_path = config_path()
    known_hosts = KNOWN_HOSTS_PATH
    to_remove = [p for p in (cfg_path, known_hosts) if os.path.exists(p)]
    # Saved per-droplet SSH keys (added in v1.0.8)
    if os.path.isdir(SERVER_KEYS_DIR):
        for name in os.listdir(SERVER_KEYS_DIR):
            full = os.path.join(SERVER_KEYS_DIR, name)
            if os.path.isfile(full):
                to_remove.append(full)

    if not to_remove:
        console.print(
            "[yellow]No local FourDollarVPN data found — nothing to remove.[/yellow]"
        )
        return

    # If a token is still readable, warn about any running droplets so
    # the user doesn't inadvertently orphan a paid server.
    token = os.environ.get("DO_API_TOKEN") or load_config().get("token")
    if token:
        try:
            do = DigitalOcean(token)
            droplets = do.list_fourdollarvpn_droplets()
            if droplets:
                console.print(
                    f"[yellow]Heads up:[/yellow] you still have "
                    f"{len(droplets)} FourDollarVPN droplet(s) running. "
                    f"After uninstalling, this CLI won't be able to "
                    f"manage them — run [bold]fourdollarvpn destroy[/bold] "
                    f"first if you want to stop billing, or go to "
                    f"[link=https://cloud.digitalocean.com/droplets]"
                    f"cloud.digitalocean.com/droplets[/link]."
                )
                for d in droplets:
                    console.print(
                        f"  {d['name']}  {d['ip']}  ({d['region']})"
                    )
                console.print()
        except DigitalOceanError:
            # Token invalid / revoked / offline — user's problem, not ours
            pass

    console.print("Will remove:")
    for p in to_remove:
        console.print(f"  {p}")

    if not args.yes:
        try:
            answer = console.input(r"Proceed? \[y/n, default: y]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer in ("n", "no"):
            console.print("Cancelled.")
            return

    for p in to_remove:
        try:
            os.remove(p)
            console.print(f"  [green]✓[/green] Removed {p}")
        except OSError as e:
            console.print(f"  [red]✗[/red] Failed to remove {p}: {e}")

    # Clean up now-empty parent directories
    for d in {
        os.path.dirname(cfg_path),
        os.path.dirname(known_hosts),
        SERVER_KEYS_DIR,
        os.path.dirname(SERVER_KEYS_DIR),
    }:
        try:
            os.rmdir(d)
        except OSError:
            pass  # not empty or gone already — fine

    console.print(
        "\n[green]Uninstall complete.[/green] The binary / script "
        "itself isn't deleted — remove it manually if you're done with it."
    )


def cmd_destroy(args):
    token = get_token(args)
    do = DigitalOcean(token)

    with console.status("Fetching FourDollarVPN droplets..."):
        droplets = do.list_fourdollarvpn_droplets()

    if not droplets:
        console.print("No FourDollarVPN droplets found.")
        return

    if args.droplet_id:
        # --droplet-id still accepts the full DO ID (for scripting)
        target = None
        for d in droplets:
            if str(d["id"]) == args.droplet_id:
                target = d
                break
        if not target:
            console.print(
                f"[red]Droplet {args.droplet_id} not found "
                f"(or not tagged as fourdollarvpn).[/red]"
            )
            sys.exit(1)
        targets = [target]
    else:
        # Show all and ask. Use a short # column for easy selection.
        table = Table(title="FourDollarVPN Droplets")
        table.add_column("#", style="bold cyan")
        table.add_column("Name")
        table.add_column("IP")
        table.add_column("Region")

        for i, d in enumerate(droplets, 1):
            table.add_row(
                str(i), d["name"], d["ip"] or "N/A", d["region"]
            )

        console.print(table)
        console.print()

        choice = console.input(
            f"Enter # to destroy (1-{len(droplets)}), 'all', or 'q' to cancel: "
        ).strip().lower()

        if choice in ("", "q", "n", "cancel"):
            console.print("Cancelled.")
            return

        if choice == "all":
            targets = droplets
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(droplets):
                    targets = [droplets[idx]]
                else:
                    raise ValueError
            except ValueError:
                console.print(
                    f"[red]Invalid selection '{choice}'. "
                    f"Enter a number 1-{len(droplets)}, 'all', or 'q'.[/red]"
                )
                sys.exit(1)

    # Confirm
    names = ", ".join(f"{d['name']} ({d['ip']})" for d in targets)
    if not args.yes:
        try:
            confirm = console.input(
                f"[yellow]Destroy {names}? This cannot be undone. (y/n, default: y): [/yellow]"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            confirm = "n"
        if confirm in ("n", "no"):
            console.print("Cancelled.")
            return

    failures = 0
    for d in targets:
        try:
            with console.status(f"Destroying {d['name']}..."):
                do.destroy_droplet(d["id"])
        except DigitalOceanError as e:
            failures += 1
            _print_error(f"Failed to destroy {d['name']} ({d['ip']}): ", e)
            continue
        # Saved SSH key is useless once the droplet is gone — clean up
        # to avoid stale files accumulating in ~/.fourdollarvpn/servers/.
        forget_droplet_key(d["id"], d.get("ip"))
        console.print(f"[green]  Destroyed {d['name']} ({d['ip']})[/green]")

    if failures:
        console.print(
            f"[red]{failures} of {len(targets)} destroy operations "
            f"failed — re-run `fourdollarvpn destroy` or check the DO dashboard.[/red]"
        )
        sys.exit(1)

    # The client .conf / .svg files generated by `add-client` and
    # `setup` live wherever the user saved them (cwd, home, or an
    # explicit --output path) — we don't track them and shouldn't
    # glob-delete, since they could belong to a different still-
    # running droplet. Just remind the user they're dead keys now.
    console.print(
        "\n[dim]The `fdvpn-*.conf` / `.svg` files generated for "
        "this droplet are now dead keys — safe to delete from wherever "
        "you saved them (working dir / home / --output path). They can't "
        "connect to anything anymore.[/dim]"
    )


def cmd_add_client(args):
    token = get_token(args)
    do = DigitalOcean(token)

    droplet = _auto_detect_droplet(do, args.ip)
    args.ip = droplet["ip"]
    if not args.ip:
        console.print(
            "[red]Selected droplet has no public IP yet — try again in "
            "a moment.[/red]"
        )
        sys.exit(1)

    console.print(
        Panel(
            "[bold]Adding VPN Client[/bold]\n"
            "by [bold cyan]SkyzFallin[/bold cyan] · "
            "[link=https://github.com/SkyzFallin/FourDollarVPN]"
            "github.com/SkyzFallin/FourDollarVPN[/link]",
            style="bold blue",
        )
    )

    ssh_key = _load_management_key_or_exit(droplet)
    try:
        # Note: this requires SSH to still be open on the droplet.
        # If --lock was used during setup, this won't work.
        # Generate client keys LOCALLY — private key never touches the server
        client_priv, client_pub = generate_keypair_local()
        # PSK generated locally too — shared once with server
        psk = generate_preshared_key()

        with SSHConnection(args.ip, ssh_key) as ssh:
            # Atomically pick next free IP, live-add the peer, and append
            # to the server config under a server-side flock. PSK is
            # streamed in via stdin so it never appears in argv / /proc.
            client_ip = add_client_and_allocate_ip(
                ssh, client_pub, psk, name=args.name
            )

            # Get server public key
            server_pub = ssh.run("wg show wg0 public-key")

            # Generate client config
            client_config = generate_client_config(
                client_priv, server_pub, psk, args.ip, client_ip
            )

        name_slug = f"{args.name}-" if args.name else ""
        # HHMM stamp keeps filenames unique across same-minute re-adds
        # without blowing the 32-char WireGuard-for-Windows tunnel-name
        # limit. The `fdvpn-` short prefix exists for the same reason;
        # `fourdollarvpn-` leaves only ~18 chars for IP + stamp.
        stamp = time.strftime("%H%M")
        default_conf = (
            f"fdvpn-{name_slug}"
            f"{client_ip.replace('.', '-')}-{stamp}.conf"
        )
        config_path = _save_with_fallback(
            args.output or default_conf,
            lambda p: _write_secret_file(p, client_config),
            is_explicit=bool(args.output),
        )

        # Also save as SVG QR (0600, no readable window)
        default_svg = config_path.replace(".conf", ".svg")
        if default_svg == config_path:
            default_svg = config_path + ".svg"
        svg_path = _save_with_fallback(
            default_svg,
            lambda p: _save_qr_svg(client_config, p),
            is_explicit=False,
        )

        if args.open_qr:
            open_in_browser(svg_path)

        svg_abs = os.path.abspath(svg_path)
        svg_link = f"[link=file://{svg_abs}]{svg_path}[/link]"
        conf_abs = os.path.abspath(config_path)
        conf_link = f"[link=file://{conf_abs}]{config_path}[/link]"

        console.print(
            Panel(
                f"[bold green]New client config saved![/bold green]\n\n"
                f"Client IP: {client_ip}\n"
                f"Config: [bold]{conf_link}[/bold]\n"
                f"QR code (SVG): [bold]{svg_link}[/bold]\n\n"
                f"Mobile: click the SVG link above to open it in your\n"
                f"browser and scan with the WireGuard app\n"
                f"(or re-run with --open-qr to auto-open the QR)\n"
                f"Desktop: import the .conf file into WireGuard",
                title="FourDollarVPN",
                style="green",
            )
        )

        console.print()
        console.print("[bold]Scan this QR code with the WireGuard mobile app:[/bold]")
        print_qr_code(client_config)

        # Now that we know what's live, offer to clean up any configs
        # sitting beside the new one that point at droplets DO no longer
        # has. Only scans the directory we actually wrote to; home dir
        # is not touched unless that's where we landed.
        try:
            live_ips = {
                d["ip"] for d in do.list_fourdollarvpn_droplets() if d.get("ip")
            }
            _offer_stale_config_cleanup(
                [os.path.dirname(os.path.abspath(config_path)) or "."],
                live_ips,
            )
        except DigitalOceanError:
            pass  # Best-effort — don't fail add-client on a flaky DO call

    except SSHError as e:
        if "Could not connect" in str(e):
            console.print(
                "[red]Cannot connect via SSH. If you used --lock during "
                "setup, SSH is disabled and new clients can't be added.[/red]"
            )
            _print_locked_ssh_help()
        else:
            _print_error("", e)
        sys.exit(1)


def _print_locked_ssh_help() -> None:
    """Explain how to recover when SSH was locked via `setup --lock`.

    The CLI can't fix it — once UFW denies 22/tcp, we can't SSH in to
    re-allow it. The only paths are DigitalOcean's browser console or
    destroy/rebuild.
    """
    console.print(
        "\n[bold]If you locked SSH with `setup --lock`, you can re-open "
        "it from the DO web console:[/bold]"
    )
    console.print(
        "  1. Go to [link=https://cloud.digitalocean.com/droplets]"
        "cloud.digitalocean.com/droplets[/link] → your droplet → "
        "Access → Launch Droplet Console"
    )
    console.print("  2. Log in as root, then run:")
    console.print("     [cyan]ufw delete deny 22/tcp[/cyan]")
    console.print("     [cyan]ufw allow 22/tcp[/cyan]")
    console.print("     [cyan]ufw reload[/cyan]")
    console.print(
        "  3. Re-run the FourDollarVPN command. The VPN itself keeps working "
        "the whole time."
    )


def _humanize_handshake(ts: int) -> str:
    """Render a Unix handshake timestamp as 'never', '42s ago', '3m ago', etc."""
    if not ts:
        return "never"
    delta = int(time.time()) - ts
    if delta < 0:
        delta = 0
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def _load_management_key_or_exit(droplet: dict):
    """Return the SSH key saved during `setup` for this droplet.

    Exits with a clear message if no key is on disk — because DigitalOcean
    only copies SSH keys into a droplet's authorized_keys at create time,
    uploading a new key now wouldn't help us log in. The saved key is the
    only way to regain management access short of DO's web console.

    Keys are indexed by droplet ID (v1.0.10+). Legacy IP-indexed keys
    from v1.0.8 / v1.0.9 are auto-migrated on first read.
    """
    key = load_droplet_key(droplet["id"], droplet.get("ip"))
    if key is not None:
        return key
    console.print(
        f"[red]No saved SSH key for {droplet['ip']} — can't manage this "
        f"droplet from the CLI.[/red]\n\n"
        f"This usually means the droplet was set up from a different "
        f"computer, or the key file at "
        f"{_droplet_key_path(droplet['id'])} was deleted.\n\n"
        f"The VPN itself is still running — existing client configs keep "
        f"working. To regain management access, run "
        f"[bold]fourdollarvpn destroy[/bold] and then "
        f"[bold]fourdollarvpn setup[/bold] to create a fresh VPN."
    )
    sys.exit(1)


def _auto_detect_droplet(
    do: DigitalOcean, explicit_ip: str | None
) -> dict:
    """Return the droplet dict to operate on, prompting if ambiguous.

    - If explicit_ip is given, look it up in the account's droplets.
    - If the user has exactly one FourDollarVPN droplet, use it.
    - If zero or no match for --ip, print an error and exit.
    - If multiple and no --ip, print the list and exit.
    """
    droplets = do.list_fourdollarvpn_droplets()
    if not droplets:
        console.print("[red]No FourDollarVPN droplets found.[/red]")
        sys.exit(1)
    if explicit_ip:
        for d in droplets:
            if d["ip"] == explicit_ip:
                return d
        console.print(
            f"[red]No FourDollarVPN droplet with IP {explicit_ip}. "
            f"Run `fourdollarvpn status` to see what's on your account.[/red]"
        )
        sys.exit(1)
    if len(droplets) == 1:
        return droplets[0]
    console.print("[red]Multiple FourDollarVPN droplets found — pass --ip to pick one:[/red]")
    for d in droplets:
        console.print(f"  {d['ip']}  {d['name']}  ({d['region']})")
    sys.exit(1)


def cmd_list_clients(args):
    """Show every peer on the VPN server, with last-handshake time."""
    token = get_token(args)
    do = DigitalOcean(token)
    droplet = _auto_detect_droplet(do, args.ip)
    server_ip = droplet["ip"]

    ssh_key = _load_management_key_or_exit(droplet)
    try:
        with SSHConnection(server_ip, ssh_key) as ssh:
            peers = list_peers(ssh)
    except (SSHError, DigitalOceanError) as e:
        _print_error("", e)
        sys.exit(1)

    if not peers:
        console.print(
            f"[yellow]No clients configured on {server_ip}.[/yellow]\n"
            "Add one with: fourdollarvpn add-client"
        )
        return

    table = Table(title=f"Clients on {server_ip}", title_justify="left")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Name")
    table.add_column("VPN IP")
    table.add_column("Last handshake")
    table.add_column("Public key (prefix)")
    for i, p in enumerate(peers, 1):
        table.add_row(
            str(i),
            p.get("name") or "-",
            p["ip"] or "-",
            _humanize_handshake(p["handshake"]),
            p["pubkey"][:12] + "…",
        )
    console.print(table)
    console.print(
        "\n[dim]Remove a client: fourdollarvpn remove-client <name|vpn-ip>[/dim]"
    )


def cmd_remove_client(args):
    """Revoke a client's access. Other clients stay connected."""
    token = get_token(args)
    do = DigitalOcean(token)
    droplet = _auto_detect_droplet(do, args.ip)
    server_ip = droplet["ip"]

    ssh_key = _load_management_key_or_exit(droplet)
    try:
        with SSHConnection(server_ip, ssh_key) as ssh:
            peers = list_peers(ssh)
            if not peers:
                console.print(
                    f"[yellow]No clients on {server_ip} to remove.[/yellow]"
                )
                return

            target = _resolve_client(peers, args.client)
            if target is None:
                sys.exit(1)

            # Confirm unless -y
            if not args.yes:
                console.print(
                    f"Remove client [bold]{target['ip'] or '?'}[/bold] "
                    f"(pubkey {target['pubkey'][:12]}…)?"
                )
                try:
                    answer = console.input(r"Remove this client? \[y/n, default: y]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = "n"
                if answer in ("n", "no"):
                    console.print("Cancelled.")
                    return

            with console.status("Removing peer..."):
                remove_peer(ssh, target["pubkey"])

            console.print(
                f"[green]✓ Removed client {target['ip']} "
                f"({target['pubkey'][:12]}…).[/green]"
            )
            console.print(
                "Its config file on any device it was installed on is now "
                "inert — re-adding requires [bold]fourdollarvpn add-client[/bold]."
            )
    except (SSHError, DigitalOceanError) as e:
        _print_error("", e)
        sys.exit(1)


def _resolve_client(peers: list, identifier: str | None) -> dict | None:
    """Find the peer matching `identifier`. Prompts interactively if None."""
    if identifier is None:
        # Interactive picker
        table = Table(title="Select a client to remove", title_justify="left")
        table.add_column("#", style="dim", justify="right")
        table.add_column("Name")
        table.add_column("VPN IP")
        table.add_column("Last handshake")
        table.add_column("Public key (prefix)")
        for i, p in enumerate(peers, 1):
            table.add_row(
                str(i),
                p.get("name") or "-",
                p["ip"] or "-",
                _humanize_handshake(p["handshake"]),
                p["pubkey"][:12] + "…",
            )
        console.print(table)
        raw = console.input(
            f"Enter # to remove (1-{len(peers)}), or 'q' to cancel: "
        ).strip().lower()
        if raw in ("", "q"):
            console.print("Cancelled.")
            return None
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(peers):
                return peers[idx]
        except ValueError:
            pass
        console.print("[red]Invalid selection.[/red]")
        return None

    # Match by exact name
    for p in peers:
        if p.get("name") and p["name"] == identifier:
            return p
    # Match by VPN IP (exact)
    for p in peers:
        if p["ip"] == identifier:
            return p
    # Match by pubkey prefix (≥ 8 chars, unambiguous)
    if len(identifier) >= 8:
        matches = [p for p in peers if p["pubkey"].startswith(identifier)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            console.print(
                f"[red]'{identifier}' matches {len(matches)} peers — "
                f"use a longer prefix or the full VPN IP.[/red]"
            )
            return None
    console.print(
        f"[red]No client matching '{identifier}'. "
        f"Try `fourdollarvpn list-clients` to see them.[/red]"
    )
    return None


def cmd_check(args):
    """SSH into the droplet and verify all services are healthy,
    including the status of the background system upgrade."""
    token = get_token(args)
    do = DigitalOcean(token)

    droplet = _auto_detect_droplet(do, args.ip)
    args.ip = droplet["ip"]
    console.print(f"Checking droplet at {args.ip}")

    console.print(
        Panel(
            "[bold]FourDollarVPN Health Check[/bold]\n"
            "by [bold cyan]SkyzFallin[/bold cyan] · "
            "[link=https://github.com/SkyzFallin/FourDollarVPN]"
            "github.com/SkyzFallin/FourDollarVPN[/link]",
            style="bold blue",
        )
    )

    ssh_key = _load_management_key_or_exit(droplet)
    try:
        with SSHConnection(args.ip, ssh_key) as ssh:
            # Collect a bunch of service/status info
            checks = {}
            checks["wg-quick@wg0"] = ssh.run(
                "systemctl is-active wg-quick@wg0", check=False
            )
            checks["ssh"] = ssh.run(
                "systemctl is-active ssh", check=False
            )
            checks["fail2ban"] = ssh.run(
                "systemctl is-active fail2ban", check=False
            )
            checks["chrony"] = ssh.run(
                "systemctl is-active chrony", check=False
            )
            checks["ufw"] = ssh.run(
                "ufw status | head -1", check=False
            )
            checks["bg_upgrade"] = ssh.run(
                "systemctl is-active fourdollarvpn-initial-upgrade "
                "2>/dev/null || echo unknown",
                check=False,
            )
            checks["bg_upgrade_result"] = ssh.run(
                "systemctl show fourdollarvpn-initial-upgrade "
                "-p Result --value 2>/dev/null || echo unknown",
                check=False,
            )
            checks["reboot_required"] = ssh.run(
                "test -f /var/run/reboot-required && "
                "echo yes || echo no",
                check=False,
            )
            checks["wg_peers"] = ssh.run(
                "wg show wg0 peers | wc -l", check=False
            )
            checks["wg_latest_handshake"] = ssh.run(
                "wg show wg0 latest-handshakes | awk '{print $2}' "
                "| sort -rn | head -1",
                check=False,
            )
            checks["listening_ports"] = ssh.run(
                "ss -tuln | awk 'NR>1 {split($5,a,\":\"); "
                "print a[length(a)]}' | sort -u | paste -sd,",
                check=False,
            )
            checks["uptime"] = ssh.run("uptime -p", check=False)

        # Pretty-print results
        def row(name: str, value: str, ok: bool):
            icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(f"  {icon} {name}: [dim]{value}[/dim]")

        console.print()
        console.print("[bold]Services:[/bold]")
        row("WireGuard (wg-quick@wg0)", checks["wg-quick@wg0"],
            checks["wg-quick@wg0"] == "active")
        row("SSH (ssh.service)", checks["ssh"],
            checks["ssh"] == "active")
        row("fail2ban", checks["fail2ban"],
            checks["fail2ban"] == "active")
        row("chrony (time sync)", checks["chrony"],
            checks["chrony"] == "active")
        row("UFW firewall", checks["ufw"],
            any(ln.strip().startswith("status: active")
                for ln in checks["ufw"].lower().splitlines()))

        console.print()
        console.print("[bold]Background system upgrade:[/bold]")
        bg_state = checks["bg_upgrade"]
        bg_result = checks["bg_upgrade_result"]
        if bg_state == "inactive" and bg_result == "success":
            row("Upgrade", "completed successfully", True)
        elif bg_state == "activating" or bg_state == "active":
            row("Upgrade", f"still running ({bg_state})", True)
        elif bg_result == "success":
            row("Upgrade", "completed successfully", True)
        else:
            row(
                "Upgrade",
                f"state={bg_state}, result={bg_result} "
                "(check `journalctl -u fourdollarvpn-initial-upgrade`)",
                False,
            )

        console.print()
        console.print("[bold]System:[/bold]")
        row("Reboot required", checks["reboot_required"],
            checks["reboot_required"] == "no")
        row("Uptime", checks["uptime"], True)
        row("Listening ports", checks["listening_ports"],
            True)

        console.print()
        console.print("[bold]WireGuard:[/bold]")
        peer_count = checks["wg_peers"].strip()
        row(f"Active peers", peer_count,
            peer_count.isdigit() and int(peer_count) > 0)
        handshake = checks["wg_latest_handshake"].strip()
        if handshake and handshake != "0":
            try:
                import datetime
                ago = int(time.time()) - int(handshake)
                if ago < 180:
                    row("Latest handshake", f"{ago}s ago", True)
                else:
                    row("Latest handshake", f"{ago}s ago "
                        "(may mean no active clients)", True)
            except ValueError:
                row("Latest handshake", handshake, True)
        else:
            row(
                "Latest handshake",
                "none yet (no client has connected)",
                True,
            )

        if checks["reboot_required"] == "yes":
            console.print()
            console.print(
                "[bold yellow]⚠  Reboot pending.[/bold yellow] A background "
                "system update installed a kernel or library that needs a "
                "reboot to take effect. The VPN keeps working in the "
                "meantime, but security patches aren't active until you "
                "reboot."
            )
            console.print(
                "[dim]  The server will auto-reboot at 04:00 UTC tonight "
                "so you can ignore this if the timing's fine. To reboot "
                "sooner: DigitalOcean dashboard (Power → Reboot), or SSH "
                "in and run `reboot`. Either way takes ~30s; the VPN "
                "reconnects automatically.[/dim]"
            )

    except SSHError as e:
        if "Could not connect" in str(e):
            console.print(
                "[red]Cannot SSH to droplet. If you used --lock during "
                "setup, SSH is disabled and health checks can't run.[/red]"
            )
            _print_locked_ssh_help()
        else:
            _print_error("", e)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="fourdollarvpn",
        description=(
            "FourDollarVPN — Set up a personal WireGuard VPN in one command.\n"
            "by SkyzFallin · https://github.com/SkyzFallin/FourDollarVPN"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # init
    init_parser = subparsers.add_parser(
        "init",
        help="Save a DigitalOcean API token for later use",
    )
    init_parser.set_defaults(func=cmd_init)

    # setup
    setup_parser = subparsers.add_parser(
        "setup", help="Create a new VPN server"
    )
    setup_parser.add_argument(
        "--token", help="DigitalOcean API token (or set DO_API_TOKEN env var)"
    )
    setup_parser.add_argument(
        "--region", help="DigitalOcean region slug (e.g. nyc1, sfo3, ams3)"
    )
    setup_parser.add_argument(
        "--lock",
        action="store_true",
        help="Disable SSH access after setup (prevents adding clients later)",
    )
    setup_parser.add_argument(
        "--output", "-o", help="Output path for client config file"
    )
    setup_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help=(
            "Skip the confirmation prompt. If an existing FourDollarVPN droplet "
            "is found, it will be destroyed and replaced."
        ),
    )
    setup_parser.add_argument(
        "--open-qr",
        action="store_true",
        help="Open the generated QR code SVG in your default browser",
    )
    setup_parser.set_defaults(func=cmd_setup)

    # status
    status_parser = subparsers.add_parser(
        "status", help="List active FourDollarVPN servers"
    )
    status_parser.add_argument("--token", help="DigitalOcean API token")
    status_parser.set_defaults(func=cmd_status)

    # destroy
    destroy_parser = subparsers.add_parser(
        "destroy", help="Tear down a VPN server"
    )
    destroy_parser.add_argument("--token", help="DigitalOcean API token")
    destroy_parser.add_argument(
        "--droplet-id", help="Specific droplet ID to destroy"
    )
    destroy_parser.add_argument(
        "-y", "--yes", action="store_true", help="Skip confirmation"
    )
    destroy_parser.set_defaults(func=cmd_destroy)

    # check
    check_parser = subparsers.add_parser(
        "check",
        help="Verify service health + background upgrade status on droplet",
    )
    check_parser.add_argument("--token", help="DigitalOcean API token")
    check_parser.add_argument(
        "--ip", help="VPN server IP (auto-detected if only one exists)"
    )
    check_parser.set_defaults(func=cmd_check)

    # add-client
    client_parser = subparsers.add_parser(
        "add-client", help="Generate a config for an additional device"
    )
    client_parser.add_argument("--token", help="DigitalOcean API token")
    client_parser.add_argument(
        "--ip", help="VPN server IP (auto-detected if only one exists)"
    )
    client_parser.add_argument(
        "--output", "-o", help="Output path for client config file"
    )
    client_parser.add_argument(
        "--open-qr",
        action="store_true",
        help="Open the generated QR code SVG in your default browser",
    )
    client_parser.add_argument(
        "--name",
        help=(
            "Optional label for this client (e.g. phone, laptop). "
            "1-32 chars, [A-Za-z0-9_-] only. Shown in list-clients "
            "and embedded in the generated filename."
        ),
    )
    client_parser.set_defaults(func=cmd_add_client)

    # list-clients
    list_parser = subparsers.add_parser(
        "list-clients",
        help="Show all devices configured on the VPN server",
    )
    list_parser.add_argument("--token", help="DigitalOcean API token")
    list_parser.add_argument(
        "--ip", help="VPN server IP (auto-detected if only one exists)"
    )
    list_parser.set_defaults(func=cmd_list_clients)

    # remove-client
    remove_parser = subparsers.add_parser(
        "remove-client",
        help="Revoke a single client's access (other clients stay connected)",
    )
    remove_parser.add_argument(
        "client",
        nargs="?",
        help=(
            "Which client to remove: the VPN IP (e.g. 10.66.66.3) or a "
            "public-key prefix of 8+ characters. Omit to pick interactively."
        ),
    )
    remove_parser.add_argument("--token", help="DigitalOcean API token")
    remove_parser.add_argument(
        "--ip", help="VPN server IP (auto-detected if only one exists)"
    )
    remove_parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt",
    )
    remove_parser.set_defaults(func=cmd_remove_client)

    # uninstall
    uninstall_parser = subparsers.add_parser(
        "uninstall",
        help="Remove FourDollarVPN's saved token and known_hosts from this machine",
    )
    uninstall_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip the confirmation prompt",
    )
    uninstall_parser.set_defaults(func=cmd_uninstall)

    args = parser.parse_args()

    # Hold the console window open at the end if the user entered the
    # guided flow (no subcommand → init + setup) on Windows. This is
    # the double-click-the-binary case where the console goes away
    # the instant the process exits, swallowing both success panels
    # and error messages. Explicit CLI invocations
    # (`fourdollarvpn setup`, etc.) skip this — they're already running
    # inside a shell whose window won't close on us.
    guided = args.command is None and sys.stdin.isatty()
    hold_window = guided and sys.platform == "win32"

    try:
        if not args.command:
            # Guided first-run flow: someone double-clicked the binary
            # (or ran `fourdollarvpn` with no subcommand). Walk them through
            # init + setup. Non-interactive shells fall through to help.
            if not sys.stdin.isatty():
                parser.print_help()
                return

            have_token = bool(
                os.environ.get("DO_API_TOKEN") or load_config().get("token")
            )
            if not have_token:
                console.print(
                    "[bold]First-time setup[/bold] — let's save your "
                    "DigitalOcean API token, then create your VPN.\n"
                )
                cmd_init(argparse.Namespace())

            # Decide what the user actually wants. If they already have a
            # FourDollarVPN server, "double-click the binary" almost always
            # means "add my new device", not "nuke my server and start
            # over." Offer a small menu.
            args = _guided_menu(parser)

        args.func(args)
    except SystemExit:
        # A command called sys.exit(N). Preserve the exit code but hold
        # the window open first so the user can see the error output.
        if hold_window:
            _press_enter_to_close()
        raise
    except BaseException:
        # Uncaught exception — Rich already printed a traceback. Hold
        # the window, then re-raise so the process still exits non-zero.
        if hold_window:
            _press_enter_to_close()
        raise

    # Normal (successful) path
    if hold_window:
        _press_enter_to_close()


def _press_enter_to_close() -> None:
    try:
        console.input("\n[dim]Press Enter to close this window...[/dim] ")
    except (EOFError, KeyboardInterrupt):
        pass


def _guided_menu(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """Interactive menu for bare-binary invocations.

    If the user has no existing FourDollarVPN droplets, fall straight through
    to `setup`. Otherwise, offer: add a device, check health, or create
    a brand-new VPN (destroying what's there). Returns the Namespace
    corresponding to whatever subcommand should run next.
    """
    # We already know there's a token (checked by caller).
    token = (
        os.environ.get("DO_API_TOKEN")
        or load_config().get("token")
    )
    do = DigitalOcean(token)

    try:
        with console.status("Checking for existing VPN servers..."):
            existing = do.list_fourdollarvpn_droplets()
    except DigitalOceanError as e:
        # Can't reach DO — fall through to setup, which will surface
        # a cleaner error if needed.
        _print_error("Could not reach DigitalOcean: ", e)
        return parser.parse_args(["setup"])

    if not existing:
        # Nothing to choose between — just provision.
        return parser.parse_args(["setup"])

    # Show what's there.
    table = Table(
        title="[bold]Your FourDollarVPN servers[/bold]",
        title_justify="left",
    )
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Region")
    table.add_column("Status")
    for d in existing:
        table.add_row(
            d["name"], d["ip"] or "N/A", d["region"], d["status"]
        )
    console.print(table)

    # Options 1 and 2 both need to SSH into the droplet, which requires
    # the local management key. If we don't have it (droplet was set up
    # on a different machine, or pre-v1.0.8), those options would just
    # dead-end. Flag them up front so the user isn't misled into picking
    # something that can't work from this machine.
    first = existing[0]
    has_key = (
        load_droplet_key(first["id"], first.get("ip")) is not None
    )
    key_note = (
        ""
        if has_key
        else "  [dim yellow](no local key — options 1 & 2 unavailable "
        "from this computer; rebuild or manage from the original "
        "machine)[/dim yellow]"
    )

    console.print("\n[bold]What would you like to do?[/bold]")
    console.print(
        "  [bold cyan]1[/bold cyan]  Add a new device "
        "(phone, laptop, etc.) to this VPN" + key_note
    )
    console.print(
        "  [bold cyan]2[/bold cyan]  See devices currently on this VPN"
        + key_note
    )
    console.print(
        "  [bold cyan]3[/bold cyan]  Remove a device from this VPN"
        + key_note
    )
    console.print(
        "  [bold cyan]4[/bold cyan]  Check that the server is "
        "running correctly" + key_note
    )
    console.print("  [bold cyan]5[/bold cyan]  Create a brand new VPN (destroys the existing one)")
    console.print("  [bold cyan]6[/bold cyan]  Destroy this VPN (stop billing)")
    console.print("  [bold cyan]7[/bold cyan]  Uninstall FourDollarVPN from this computer")
    console.print("  [bold cyan]q[/bold cyan]  Quit")

    # If there's more than one droplet, options 1-4 need an IP; auto-pick
    # the first for simplicity in the guided flow.
    server_ip = existing[0]["ip"] or ""
    ssh_dependent = ("1", "2", "3", "4")

    while True:
        try:
            choice = console.input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\nCancelled.")
            sys.exit(0)

        if choice in ("", "q", "quit", "exit"):
            console.print("Bye.")
            sys.exit(0)
        if choice in ssh_dependent and not has_key:
            console.print(
                "[red]Can't do that from this computer — there's no local "
                "SSH key for this droplet. It was probably set up on a "
                "different machine. Either manage it from the original "
                "machine, or pick option 5 to rebuild.[/red]"
            )
            continue
        if choice == "1":
            if len(existing) > 1:
                console.print(
                    f"[dim](Adding to {existing[0]['name']} — the first "
                    f"one above. Use `fourdollarvpn add-client --ip ...` if "
                    f"you meant a different server.)[/dim]"
                )
            cmd_args = ["add-client", "--open-qr"]
            if server_ip:
                cmd_args += ["--ip", server_ip]
            return parser.parse_args(cmd_args)
        if choice == "2":
            cmd_args = ["list-clients"]
            if server_ip:
                cmd_args += ["--ip", server_ip]
            return parser.parse_args(cmd_args)
        if choice == "3":
            # remove-client will prompt interactively for which peer to
            # remove since we don't pass an identifier.
            cmd_args = ["remove-client"]
            if server_ip:
                cmd_args += ["--ip", server_ip]
            return parser.parse_args(cmd_args)
        if choice == "4":
            cmd_args = ["check"]
            if server_ip:
                cmd_args += ["--ip", server_ip]
            return parser.parse_args(cmd_args)
        if choice == "5":
            # Destroy ONLY the displayed droplet, then fall through to a
            # normal `setup`. Passing `-y` to setup would nuke every
            # fourdollarvpn-prefixed droplet in the account, not just the one
            # shown in the menu above.
            target = existing[0]
            try:
                with console.status(f"Destroying {target['name']}..."):
                    do.destroy_droplet(target["id"])
            except DigitalOceanError as e:
                _print_error(
                    f"Failed to destroy {target['name']}: ", e
                )
                sys.exit(1)
            forget_droplet_key(target["id"], target.get("ip"))
            console.print(
                f"[green]Destroyed {target['name']} ({target['ip']}).[/green]"
            )
            return parser.parse_args(["setup"])
        if choice == "6":
            # Target the first droplet explicitly so multi-droplet users
            # don't accidentally wipe more than they meant to.
            return parser.parse_args([
                "destroy", "-y", "--droplet-id", str(existing[0]["id"]),
            ])
        if choice == "7":
            return parser.parse_args(["uninstall"])
        console.print("[red]Enter 1, 2, 3, 4, 5, 6, 7, or q.[/red]")


if __name__ == "__main__":
    main()
