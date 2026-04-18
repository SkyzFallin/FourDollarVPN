from __future__ import annotations

import hashlib
import io
import time

import paramiko
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from rich.console import Console

API_BASE = "https://api.digitalocean.com/v2"
DROPLET_NAME_PREFIX = "fourdollarvpn-"
DROPLET_TAG = "fourdollarvpn"
DROPLET_IMAGE = "ubuntu-24-04-x64"
DROPLET_SIZE = "s-1vcpu-512mb-10gb"

console = Console()


class DigitalOceanError(Exception):
    pass


class DigitalOcean:
    def __init__(self, token: str):
        self.token = token
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        )

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = f"{API_BASE}{path}"
        kwargs.setdefault("timeout", (10, 30))
        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.Timeout as e:
            raise DigitalOceanError(
                "DigitalOcean API timed out. Check your connection and try again."
            ) from e
        except requests.ConnectionError as e:
            raise DigitalOceanError(
                f"Could not reach DigitalOcean API: {e}"
            ) from e
        if resp.status_code == 401:
            raise DigitalOceanError(
                "Invalid API token. Check your token and try again."
            )
        if resp.status_code == 429:
            raise DigitalOceanError(
                "Rate limited by DigitalOcean. Wait a minute and try again."
            )
        if not resp.ok:
            try:
                msg = resp.json().get("message", resp.text[:500])
            except ValueError:
                msg = resp.text[:500]
            raise DigitalOceanError(f"API error ({resp.status_code}): {msg}")
        if resp.status_code == 204:
            return {}
        try:
            return resp.json()
        except ValueError as e:
            raise DigitalOceanError(
                f"DigitalOcean returned non-JSON response: {resp.text[:500]}"
            ) from e

    def verify_token(self):
        self._request("GET", "/account")

    def list_regions(self) -> list[dict]:
        data = self._request("GET", "/regions")
        return [r for r in data["regions"] if r["available"]]

    def upload_ssh_key(self, key: paramiko.Ed25519Key, name: str) -> int:
        pub_key = f"{key.get_name()} {key.get_base64()}"
        fingerprint = hashlib.md5(key.asbytes()).hexdigest()
        fingerprint = ":".join(
            fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)
        )

        # If a key with the same fingerprint already exists, reuse it —
        # but ONLY if it's a FourDollarVPN-managed key. Otherwise we could
        # end up "reusing" the user's own key and later delete it
        # during cleanup. Astronomically-unlikely fingerprint collisions
        # on freshly-generated Ed25519 keys aside, it's also a way to
        # recover gracefully from a prior partial-run that left its
        # ephemeral key orphaned in the account.
        existing = self._request("GET", "/account/keys")
        for k in existing["ssh_keys"]:
            if k["fingerprint"] == fingerprint and k.get("name", "").startswith(
                DROPLET_NAME_PREFIX
            ):
                return k["id"]

        data = self._request(
            "POST",
            "/account/keys",
            json={"name": name, "public_key": pub_key},
        )
        return data["ssh_key"]["id"]

    def delete_ssh_key(self, key_id: int):
        try:
            self._request("DELETE", f"/account/keys/{key_id}")
        except DigitalOceanError:
            pass  # Best effort cleanup

    def create_droplet(
        self, name: str, region: str, ssh_key_id: int
    ) -> dict:
        data = self._request(
            "POST",
            "/droplets",
            json={
                "name": name,
                "region": region,
                "size": DROPLET_SIZE,
                "image": DROPLET_IMAGE,
                "ssh_keys": [ssh_key_id],
                "ipv6": False,
            },
        )
        droplet = data["droplet"]
        # Tag as a best-effort follow-up rather than in the create payload.
        # Some DO tokens don't carry tag:create, which would reject the
        # entire droplet-create request — not worth trading provisioning
        # reliability for a tag. If this fails, list_fourdollarvpn_droplets
        # still finds the droplet via the name-prefix fallback.
        try:
            # Create the tag first (idempotent on DO's side — returns an
            # existing tag). If the token lacks tag:create, this 403s and
            # the subsequent POST would 404; both caught below.
            self._request("POST", "/tags", json={"name": DROPLET_TAG})
        except DigitalOceanError:
            pass
        try:
            self._request(
                "POST",
                f"/tags/{DROPLET_TAG}/resources",
                json={
                    "resources": [
                        {"resource_id": str(droplet["id"]),
                         "resource_type": "droplet"}
                    ]
                },
            )
        except DigitalOceanError:
            pass
        return droplet

    def wait_for_droplet(self, droplet_id: int, timeout: int = 300) -> str:
        start = time.time()
        while time.time() - start < timeout:
            data = self._request("GET", f"/droplets/{droplet_id}")
            droplet = data["droplet"]
            if droplet["status"] == "active":
                for net in droplet["networks"]["v4"]:
                    if net["type"] == "public":
                        return net["ip_address"]
            time.sleep(5)
        raise DigitalOceanError(
            f"Droplet did not become active within {timeout}s"
        )

    def list_fourdollarvpn_droplets(self) -> list[dict]:
        """Return all FourDollarVPN-managed droplets on the account.

        A droplet counts as FourDollarVPN-managed if it carries the
        `fourdollarvpn` tag (set at creation time from v1.0.10 onward) OR
        its name starts with `fourdollarvpn-` (covers droplets from earlier
        versions that predate tagging). We walk `/droplets` once and
        union both, rather than calling the tag endpoint separately,
        so there's a single code path and no double pagination.
        """
        droplets = []
        seen_ids: set[int] = set()
        path = "/droplets?per_page=200"
        while path:
            data = self._request("GET", path)
            for d in data.get("droplets", []):
                tags = d.get("tags") or []
                if not (
                    DROPLET_TAG in tags
                    or d["name"].startswith(DROPLET_NAME_PREFIX)
                ):
                    continue
                if d["id"] in seen_ids:
                    continue
                seen_ids.add(d["id"])
                ip = None
                for net in d["networks"]["v4"]:
                    if net["type"] == "public":
                        ip = net["ip_address"]
                droplets.append(
                    {
                        "id": d["id"],
                        "name": d["name"],
                        "ip": ip,
                        "region": d["region"]["slug"],
                        "status": d["status"],
                        "created_at": d["created_at"],
                    }
                )
            next_url = (
                data.get("links", {})
                .get("pages", {})
                .get("next")
            )
            if next_url and next_url.startswith(API_BASE):
                path = next_url[len(API_BASE):]
            else:
                path = None
        return droplets

    def destroy_droplet(self, droplet_id: int):
        self._request("DELETE", f"/droplets/{droplet_id}")

    def generate_ssh_keypair(self) -> tuple[paramiko.Ed25519Key, str]:
        """Generate a fresh ephemeral Ed25519 keypair for droplet provisioning.

        Returns (paramiko_key, openssh_pem_str). The PEM string lets the
        caller persist the private key to disk — paramiko's Ed25519Key
        doesn't implement write_private_key, so we keep the original PEM
        around instead of trying to round-trip through paramiko.
        """
        # Paramiko doesn't have Ed25519Key.generate(); use `cryptography` to
        # create the private key, serialize to OpenSSH, then load into paramiko.
        priv = Ed25519PrivateKey.generate()
        openssh_bytes = priv.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.OpenSSH,
            encryption_algorithm=NoEncryption(),
        )
        openssh_str = openssh_bytes.decode()
        paramiko_key = paramiko.Ed25519Key.from_private_key(
            io.StringIO(openssh_str)
        )
        return paramiko_key, openssh_str
