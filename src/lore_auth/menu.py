"""Simple student/instructor menu for lore-auth + lore server."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from . import admin_cli
from .detect import detect_init
from .loreserver_config import write_loreserver_auth_toml
from .services import ServiceSpec, is_running, read_pid, start_background, stop_service
from .setup_lore import DEFAULT_REMOTE, LoreSetup, auto_setup_lore, setup_path_for_users

DEFAULT_USERS = Path("/opt/lore-auth/data") / "users.json"
DEFAULT_CERTS = Path("/opt/lore-auth/certs")
GRPC_PORT = 50051
HTTP_PORT = 8443


@dataclass
class Paths:
    users: Path
    private_key: Path
    cert: Path
    key: Path

    @classmethod
    def from_users(cls, users: Path) -> "Paths":
        data = users.parent
        return cls(
            users=users,
            private_key=data / "signing-private.pem",
            cert=DEFAULT_CERTS / "cert.pem",
            key=DEFAULT_CERTS / "key.pem",
        )

    @property
    def loreserver_overlay(self) -> Path:
        return self.users.parent / "loreserver-auth.toml"

    @property
    def lore_config_hint(self) -> Path:
        return self.users.parent / "loreserver-config-path.txt"


def _pause() -> None:
    try:
        input("\nPress Enter to continue...")
    except EOFError:
        pass


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        try:
            raw = input(f"{prompt}{suffix}: ").strip()
        except EOFError:
            print()
            return default or ""
        if raw:
            return raw
        if default is not None:
            return default
        print("  Please enter a value.")


def _menu(title: str, options: list[tuple[str, str]], *, allow_back: bool = True) -> str | None:
    while True:
        print()
        print("=" * 44)
        print(title)
        print("=" * 44)
        for num, label in options:
            print(f"  {num}. {label}")
        if allow_back:
            print("  0. Back")
        try:
            choice = input("\nSelect: ").strip()
        except EOFError:
            print()
            return None
        if allow_back and choice == "0":
            return None
        if choice in {n for n, _ in options}:
            return choice
        print("  Invalid choice — try again.")


def _resolve_users_path(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("LORE_AUTH_USERS")
    if env:
        return Path(env)
    if DEFAULT_USERS.is_file():
        return DEFAULT_USERS
    return Path("dev-data") / "users.json"


def _load_setup(users_path: Path) -> LoreSetup | None:
    return LoreSetup.load(setup_path_for_users(users_path))


def ensure_lore_setup(users_path: Path) -> LoreSetup | None:
    existing = _load_setup(users_path)
    if existing and existing.default_repo_id:
        return existing
    print("Setting up Lore (auto)…")
    try:
        setup = auto_setup_lore(users_path, remote_url=DEFAULT_REMOTE, quiet=False)
        print(f"Class repo: {setup.default_repo_name}")
        return setup
    except Exception as exc:  # noqa: BLE001
        print(f"Auto Setup Lore failed: {exc}")
        return None



def ensure_service_dirs() -> None:
    """Create /opt/lore-auth/run and log for background PIDs; sudo+chown if needed."""
    from .services import LOG_DIR, RUN_DIR

    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"
    dirs = (RUN_DIR, LOG_DIR)

    def _writable(d: Path) -> bool:
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    if all(_writable(d) for d in dirs):
        return
    print("Creating runtime dirs for background servers (sudo may ask for a password)…")
    _sudo(["mkdir", "-p", str(RUN_DIR), str(LOG_DIR)])
    _sudo(["chown", "-R", f"{user}:{user}", str(RUN_DIR), str(LOG_DIR)])
    for d in dirs:
        if not _writable(d):
            raise RuntimeError(f"Still cannot write {d} after sudo chown")


def _sudo(cmd: list[str]) -> None:
    full = ["sudo", *cmd]
    print("+", " ".join(full))
    proc = subprocess.run(full, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(full)}")


def tls_ready(paths: Paths) -> bool:
    return paths.cert.is_file() and paths.key.is_file()


def overlay_ready(paths: Paths) -> bool:
    return paths.loreserver_overlay.is_file()


def data_ready(paths: Paths) -> tuple[bool, list[str]]:
    missing: list[str] = []
    if not paths.users.is_file():
        missing.append("users.json (init)")
    if not paths.private_key.is_file():
        missing.append("signing-private.pem (init)")
    if paths.users.is_file():
        try:
            from .users import UsersConfig

            cfg = UsersConfig.load(paths.users)
            if not cfg.codes:
                missing.append("at least one user")
            if not (cfg.issuer or "").strip():
                missing.append("issuer in users.json")
        except Exception as exc:  # noqa: BLE001
            missing.append(f"users.json ({exc})")
    return len(missing) == 0, missing


def auth_start_ready(paths: Paths) -> tuple[bool, list[str]]:
    ok, missing = data_ready(paths)
    if not tls_ready(paths):
        missing = [*missing, "TLS cert/key (Setup authentication server)"]
        ok = False
    if not overlay_ready(paths):
        missing = [*missing, "loreserver-auth.toml (Setup authentication server)"]
        ok = False
    return ok, missing


def public_base_url_from_users(users_path: Path) -> str:
    from .users import UsersConfig

    cfg = UsersConfig.load(users_path)
    issuer = (cfg.issuer or "").rstrip("/")
    if not issuer:
        raise RuntimeError("users.json missing issuer")
    hostport = issuer.split("://", 1)[-1].split("/")[0]
    if ":" in hostport:
        return issuer
    return f"{issuer}:{HTTP_PORT}"


def find_loreserver_bin() -> str | None:
    return shutil.which("loreserver") or shutil.which("lore-server")


def resolve_lore_config_path(paths: Paths) -> Path | None:
    """Return loreserver --config path (file OR directory)."""
    env = os.environ.get("LORESERVER_CONFIG")
    if env:
        p = Path(env)
        if p.exists():
            return p
    if paths.lore_config_hint.is_file():
        p = Path(paths.lore_config_hint.read_text(encoding="utf-8").strip())
        if p.exists():
            return p
    for cand in (
        Path("/opt/loreserver/config"),
        Path("/opt/loreserver/config/local.toml"),
        Path("/opt/lore/loreserver.toml"),
        Path("/opt/loreserver/config.toml"),
        Path("/etc/loreserver/config.toml"),
        Path.home() / "loreserver.toml",
        Path.home() / "lore" / "server.toml",
    ):
        if cand.exists():
            return cand
    return None


def lore_merge_target(config_path: Path) -> Path:
    """Where to write/merge auth TOML. Config dir -> local.toml inside it."""
    if config_path.is_dir():
        return config_path / "local.toml"
    return config_path


def lore_config_arg(config_path: Path) -> str:
    """Argument for loreserver --config (prefers the directory form)."""
    if config_path.is_dir():
        return str(config_path)
    if config_path.name == "local.toml" and config_path.parent.is_dir():
        return str(config_path.parent)
    return str(config_path)


def action_setup_auth_server(paths: Paths) -> None:
    print()
    print("Setup authentication server")
    try:
        ensure_service_dirs()
    except Exception as exc:  # noqa: BLE001
        print(f"Could not prepare run/log dirs: {exc}")
        _pause()
        return
    try:
        det = detect_init(out=paths.users.parent)
        dns = det.dns_name
    except Exception as exc:  # noqa: BLE001
        print(f"Could not read Tailscale MagicDNS name: {exc}")
        _pause()
        return

    print(f"This machine MagicDNS name: {dns}")

    if not tls_ready(paths):
        print()
        print("Before continuing: Tailscale Admin → DNS → Enable HTTPS")
        try:
            input("Press Enter after HTTPS Certificates is enabled...")
        except EOFError:
            pass
        home = Path.home()
        for p in (home / f"{dns}.crt", home / f"{dns}.key"):
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass
        print("Requesting Tailscale certificate (sudo may ask for a password)…")
        try:
            proc = subprocess.run(
                ["sudo", "tailscale", "cert", dns],
                cwd=str(home),
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"tailscale cert failed (exit {proc.returncode})")
            src_crt = home / f"{dns}.crt"
            src_key = home / f"{dns}.key"
            if not src_crt.is_file() or not src_key.is_file():
                raise RuntimeError("cert files not found after tailscale cert")
            _sudo(["mkdir", "-p", str(DEFAULT_CERTS)])
            _sudo(["mv", str(src_crt), str(paths.cert)])
            _sudo(["mv", str(src_key), str(paths.key)])
            _sudo(["chmod", "600", str(paths.key)])
            user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"
            _sudo(["chown", "-R", f"{user}:{user}", str(DEFAULT_CERTS)])
        except Exception as exc:  # noqa: BLE001
            print(f"Failed: {exc}")
            _pause()
            return
        print("TLS cert installed.")
    else:
        print("TLS cert already present.")

    overlay = write_loreserver_auth_toml(
        paths.loreserver_overlay,
        dns_name=dns,
        grpc_port=GRPC_PORT,
        http_port=HTTP_PORT,
    )
    print(f"\nWrote {overlay}")
    print(overlay.read_text(encoding="utf-8"))

    # Remember loreserver main config path if we can find / ask once
    cfg = resolve_lore_config_path(paths)
    if cfg is None:
        print("Could not auto-find the main loreserver config file.")
        typed = _ask("Path to loreserver config TOML (or leave empty to skip)", default="")
        if typed:
            cfg = Path(typed)
            if cfg.is_file():
                paths.lore_config_hint.write_text(str(cfg.resolve()) + "\n", encoding="utf-8")
            else:
                print(f"Not found: {cfg}")
                cfg = None
    else:
        paths.lore_config_hint.write_text(str(cfg.resolve()) + "\n", encoding="utf-8")
        print(f"Detected loreserver config: {cfg}")

    if cfg and cfg.exists():
        merge_path = lore_merge_target(cfg)
        if not merge_path.is_file() and cfg.is_dir():
            merge_path.write_text("", encoding="utf-8")
        if not merge_path.is_file():
            print(f"Merge target missing: {merge_path}")
            _pause()
            return
        # Append overlay marker if not already present
        text = merge_path.read_text(encoding="utf-8")
        marker = "# BEGIN lore-auth-generated"
        block = (
            f"\n{marker}\n"
            + paths.loreserver_overlay.read_text(encoding="utf-8")
            + "# END lore-auth-generated\n"
        )
        if marker in text:
            pre = text.split(marker, 1)[0].rstrip()
            # drop old generated section
            if "# END lore-auth-generated" in text:
                post = text.split("# END lore-auth-generated", 1)[1]
            else:
                post = ""
            merge_path.write_text(pre + "\n" + block + post.lstrip("\n"), encoding="utf-8")
        else:
            merge_path.write_text(text.rstrip() + "\n" + block, encoding="utf-8")
        print(f"Merged auth settings into {merge_path}")
        print("If loreserver is already running, use Shut down / Start lore server to apply.")
    else:
        print("Skipped merging into loreserver config (path unknown).")
        print(f"Manually merge {overlay} into loreserver, or re-run Setup and enter the path.")

    _pause()


def action_start_auth(paths: Paths) -> None:
    try:
        ensure_service_dirs()
    except Exception as exc:  # noqa: BLE001
        print(f"Cannot prepare run/log dirs: {exc}")
        _pause()
        return
    ok, missing = auth_start_ready(paths)
    if not ok:
        print("Cannot start authentication server. Missing:")
        for m in missing:
            print(f"  - {m}")
        _pause()
        return
    base = public_base_url_from_users(paths.users)
    python = sys.executable
    argv = [
        python,
        "-m",
        "lore_auth",
        "--users",
        str(paths.users),
        "--private-key",
        str(paths.private_key),
        "--cert",
        str(paths.cert),
        "--key",
        str(paths.key),
        "--public-base-url",
        base,
        "--grpc-host",
        "0.0.0.0",
        "--grpc-port",
        str(GRPC_PORT),
        "--http-host",
        "0.0.0.0",
        "--http-port",
        str(HTTP_PORT),
    ]
    try:
        pid = start_background(ServiceSpec.auth(), argv)
        print(f"Authentication server started in background (pid {pid}).")
        print(f"Log: {ServiceSpec.auth().log_file}")
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to start: {exc}")
    _pause()


def action_stop_auth() -> None:
    try:
        stop_service(ServiceSpec.auth())
        print("Authentication server stopped.")
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to stop: {exc}")
    _pause()


def action_start_lore(paths: Paths) -> None:
    try:
        ensure_service_dirs()
    except Exception as exc:  # noqa: BLE001
        print(f"Cannot prepare run/log dirs: {exc}")
        _pause()
        return
    bin_path = find_loreserver_bin()
    if not bin_path:
        print("`loreserver` not found on PATH.")
        print("Install Lore server tools or add them to PATH, then try again.")
        _pause()
        return
    cfg = resolve_lore_config_path(paths)
    if not cfg:
        print("loreserver config path unknown.")
        typed = _ask(
            "Path to loreserver --config (file or directory)",
            default="/opt/loreserver/config",
        )
        if not typed or not Path(typed).exists():
            print("No valid config path.")
            _pause()
            return
        cfg = Path(typed)
    paths.lore_config_hint.write_text(str(cfg.resolve()) + "\n", encoding="utf-8")

    # Ensure auth overlay exists / merged
    if not overlay_ready(paths):
        print("Run Setup authentication server first (writes auth TOML).")
        _pause()
        return

    argv = [bin_path, "--config", lore_config_arg(cfg)]
    # Some builds use different flags; try --config first
    try:
        pid = start_background(ServiceSpec.lore(), argv)
        print(f"Lore server started in background (pid {pid}).")
        print(f"Log: {ServiceSpec.lore().log_file}")
        print(f"Config: {cfg}")
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to start with `--config`: {exc}")
        print("Check the log and your loreserver CLI flags.")
    _pause()


def action_stop_lore() -> None:
    try:
        stop_service(ServiceSpec.lore())
        print("Lore server stopped.")
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to stop: {exc}")
    _pause()


def action_add_user(users_path: Path) -> None:
    setup = ensure_lore_setup(users_path)
    if not setup or not setup.default_repo_id:
        print("Cannot add users until Lore repo setup succeeds.")
        _pause()
        return
    kind = _menu(
        "New user — pick a role",
        [("1", "Regular user (read, write)"), ("2", "Admin user (read, write, admin)")],
    )
    if kind is None:
        return
    permissions = "read,write,admin" if kind == "2" else "read,write"
    username = _ask("Username")
    if not username or not users_path.is_file():
        return
    print(f"\nCreating {username} on {setup.default_repo_name}…")
    code = admin_cli.cmd_add_user(
        SimpleNamespace(
            users=str(users_path),
            username=username,
            name=username,
            repo=setup.default_repo_id,
            permissions=permissions,
            secret=None,
            force=False,
        )
    )
    if code != 0:
        again = _menu(
            f"User '{username}' may already exist. Overwrite?",
            [("1", "Yes, overwrite"), ("2", "No, cancel")],
            allow_back=False,
        )
        if again == "1":
            admin_cli.cmd_add_user(
                SimpleNamespace(
                    users=str(users_path),
                    username=username,
                    name=username,
                    repo=setup.default_repo_id,
                    permissions=permissions,
                    secret=None,
                    force=True,
                )
            )
    print("\nGive the student the secret shown above (once).")
    _pause()


def action_list(users_path: Path) -> None:
    if users_path.is_file():
        admin_cli.cmd_list(SimpleNamespace(users=str(users_path)))
    else:
        print(f"Missing {users_path}")
    _pause()


def action_disable(users_path: Path) -> None:
    if not users_path.is_file():
        print(f"Missing {users_path}")
        _pause()
        return
    username = _ask("Username to disable")
    admin_cli.cmd_disable_user(SimpleNamespace(users=str(users_path), username=username))
    _pause()


def action_init_if_needed(paths: Paths) -> None:
    if paths.users.is_file() and paths.private_key.is_file():
        return
    print("First-time init (auto from Tailscale)…")
    admin_cli.cmd_init(
        SimpleNamespace(
            auto=True,
            out=str(paths.users.parent),
            issuer=None,
            audience="",
            env="team3",
            ttl_hours=12,
            force=False,
        )
    )
    _pause()


def run_menu(*, users: str | None = None) -> int:
    users_path = _resolve_users_path(users)
    paths = Paths.from_users(users_path)
    try:
        paths.users.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    print(f"lore-auth  |  {users_path}")
    if not paths.users.is_file() or not paths.private_key.is_file():
        action_init_if_needed(paths)
        paths = Paths.from_users(_resolve_users_path(users))

    setup = ensure_lore_setup(paths.users) if paths.users.is_file() else None
    if setup:
        print(f"class repo: {setup.default_repo_name}")

    auth_spec = ServiceSpec.auth()
    lore_spec = ServiceSpec.lore()

    while True:
        auth_on = is_running(auth_spec)
        lore_on = is_running(lore_spec)
        can_start_auth, missing_auth = auth_start_ready(paths)
        need_setup = (not tls_ready(paths)) or (not overlay_ready(paths))

        print()
        print("=" * 44)
        print("LoreAuth")
        print("=" * 44)
        if setup:
            print(f"  repo: {setup.default_repo_name}")
        print(f"  authentication server: {'RUNNING' if auth_on else 'stopped'}")
        print(f"  lore server:           {'RUNNING' if lore_on else 'stopped'}")
        print()
        print("  1. Enter new user")
        print("  2. List users")
        print("  3. Disable user")

        n = 4
        keymap: dict[str, str] = {}
        if need_setup:
            print(f"  {n}. Setup authentication server")
            keymap[str(n)] = "setup_auth"
            n += 1
        if auth_on:
            print(f"  {n}. Shut down authentication server")
            keymap[str(n)] = "stop_auth"
            n += 1
        elif can_start_auth:
            print(f"  {n}. Start authentication server")
            keymap[str(n)] = "start_auth"
            n += 1
        else:
            print("  (Start authentication server hidden — finish Setup / add a user first)")
            for m in missing_auth:
                print(f"    - {m}")

        if lore_on:
            print(f"  {n}. Shut down lore server")
            keymap[str(n)] = "stop_lore"
            n += 1
        else:
            print(f"  {n}. Start lore server")
            keymap[str(n)] = "start_lore"
            n += 1

        print("  0. Quit")
        try:
            choice = input("\nSelect: ").strip()
        except EOFError:
            print()
            return 0

        if choice == "0":
            print("Bye.")
            return 0
        if choice == "1":
            action_add_user(paths.users)
            setup = _load_setup(paths.users)
        elif choice == "2":
            action_list(paths.users)
        elif choice == "3":
            action_disable(paths.users)
        elif choice in keymap:
            act = keymap[choice]
            if act == "setup_auth":
                action_setup_auth_server(paths)
                paths = Paths.from_users(paths.users)
            elif act == "start_auth":
                action_start_auth(paths)
            elif act == "stop_auth":
                action_stop_auth()
            elif act == "start_lore":
                action_start_lore(paths)
            elif act == "stop_lore":
                action_stop_lore()
        else:
            print("  Invalid choice — try again.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lore-auth-menu")
    p.add_argument("--users", default=None)
    args = p.parse_args(argv)
    return run_menu(users=args.users)


if __name__ == "__main__":
    raise SystemExit(main())
