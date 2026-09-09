# lore-auth

Free, Tailscale-only UCS auth for **stock LoreGUI** Connect.

- Access codes in `users.json` (no OIDC, Entra, passwords, or SQLite)
- RS256 JWTs + JWKS (`kid` required)
- gRPC `epic_urc.UrcAuthApi` + HTTPS `/login` + `/.well-known/jwks.json`
- **$0** — Tailscale MagicDNS HTTPS certs only; **no** LoreGUI / lore / loreserver patches

See sibling design doc: `../lore-auth-design.md`.

## Layout

```
lore-auth/
  proto/auth_api.proto          # copied from lore pin checkout
  scripts/gen_proto.py
  src/lore_auth/                # server + admin helpers
  examples/
  tests/
  requirements.txt
```

## Install (Windows / Linux)

```powershell
cd C:\Users\tomas.arcegil\Desktop\LoreAuth\lore-auth
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
pip install -e .
python scripts/gen_proto.py
```

Linux:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
python scripts/gen_proto.py
```

## Admin: init + add user

```powershell
# Issuer MUST be the MagicDNS HTTPS hostname students will use
python -m lore_auth.admin_cli init `
  --out dev-data `
  --issuer https://lore-auth.<tailnet>.ts.net `
  --audience "lore-host.<tailnet>.ts.net,.<tailnet>.ts.net" `
  --env team3

python -m lore_auth.admin_cli add-user `
  --users dev-data/users.json `
  --username tomas `
  --name Tomas `
  --repo 01a066401a037f92bf808b2282c34bb3 `
  --permissions read,write,admin

python -m lore_auth.admin_cli list --users dev-data/users.json
```

Other commands: `disable-user`, `rotate-secret`, `set-repo`.

Console scripts (after `pip install -e .`): `lore-auth` and `lore-auth-admin`.

## Run server

### Dev smoke (HTTP + insecure gRPC — local only)

```powershell
python -m lore_auth `
  --users dev-data/users.json `
  --private-key dev-data/signing-private.pem `
  --public-base-url http://127.0.0.1:8443 `
  --grpc-host 127.0.0.1 --grpc-port 50051 `
  --http-host 127.0.0.1 --http-port 8443 `
  --dev
```

Check JWKS:

```powershell
Invoke-WebRequest http://127.0.0.1:8443/.well-known/jwks.json | Select-Object -ExpandProperty Content
```

### Production (Tailscale MagicDNS HTTPS)

On the VM (Ubuntu typical):

```bash
# Tailscale Admin: enable MagicDNS + HTTPS Certificates
sudo tailscale cert lore-auth.<tailnet>.ts.net
# install cert.pem / key.pem under /opt/lore-auth/certs/ (key mode 0600)

python -m lore_auth \
  --users /opt/lore-auth/users.json \
  --private-key /opt/lore-auth/signing-private.pem \
  --cert /opt/lore-auth/certs/cert.pem \
  --key /opt/lore-auth/certs/key.pem \
  --public-base-url https://lore-auth.<tailnet>.ts.net \
  --grpc-host 0.0.0.0 --grpc-port 443 \
  --http-host 0.0.0.0 --http-port 8443
```

Notes:

- Lore client rewrites `ucs-auth://host` → `https://host`. Plain HTTP will not satisfy Connect.
- Prefer MagicDNS FQDN as `iss` / `auth_url` / JWKS URL — never the `100.x` IP.
- gRPC and HTTP are separate ports in this implementation (simpler stack). Point `auth_url` at the **gRPC** TLS host:port if not sharing 443; if you terminate both on 443 via a reverse proxy, that is fine too. For same-host Tailscale, common pattern: gRPC on 443, HTTP login/JWKS on 8443 **or** put a reverse proxy in front. For class VM with one cert, you can set `--grpc-port 443` and `--http-port 443` only if you front with a multiplexer; default is split ports.
- **Recommended class layout:** put HTTP on **443** (login + JWKS) and gRPC on another port only if the client allows a port in the auth host. Stock UCS uses the host from `auth_url` on **443** for gRPC. So for production, prefer **gRPC on 443** and serve `/login` + JWKS on the **same** HTTPS port via a reverse proxy, **or** run HTTP also needing discovery on a path the client never hits for gRPC.

**Practical default for this package without a reverse proxy:**

1. Set loreserver `auth_url = "ucs-auth://lore-auth.<tailnet>.ts.net"` (gRPC TLS **:443**).
2. Run lore-auth with `--grpc-port 443 --cert … --key …`.
3. Also expose JWKS + login on HTTPS. Options:
   - reverse proxy (nginx/caddy) on 443 routing HTTP/1.1 paths vs h2 gRPC, **or**
   - run HTTP on 443 and gRPC on a different advertised host (not stock-friendly), **or**
   - use `--http-port 443` with a process that only does HTTP if you put gRPC behind the same port differently.

Simplest student-path without nginx: use **two MagicDNS names** or put **Caddy** in front. For bring-up testing, `--dev` on localhost is enough.

JWKS endpoint for loreserver must be reachable at HTTPS:

`https://lore-auth.<tailnet>.ts.net/.well-known/jwks.json`

If HTTP is on 8443, either proxy `/.well-known` and `/login` from 443, or set JWKS URL to include `:8443` (works if loreserver allows port in URL).

## loreserver TOML

See `examples/loreserver-auth.toml.example`. Required bits:

```toml
[environment.endpoint]
auth_url = "ucs-auth://lore-auth.<tailnet>.ts.net"

[server.auth.jwk]
endpoint = "https://lore-auth.<tailnet>.ts.net/.well-known/jwks.json"
```

## Student flow

1. Join Tailscale; MagicDNS on.
2. LoreGUI → Connect to lore remote.
3. Browser opens `/login?session=…` → enter access code → Submit.
4. LoreGUI polls `GetAuthSession` → Connected.
5. Repo ops call `ExchangeUserTokenForMultiresourceToken` (Bearer AuthN → AuthZ with `resources`).

## Tests

```powershell
python -m unittest tests.test_jwt_and_acl -v
```

## Implemented RPCs

| RPC | Behavior |
|-----|----------|
| `HealthCheck` | `status=ok` |
| `StartAuthSession` | session_code + login_url |
| `GetAuthSession` | optional UserToken when login done |
| `ExchangeUserTokenForMultiresourceToken` | Bearer AuthN → AuthZ `token` |
| others | `UNIMPLEMENTED` |

## Constraints (locked)

- Free / Tailscale MagicDNS HTTPS only
- No LoreGUI / lore patches
- No OIDC / Entra / SQLite passwords — `users.json` access codes only
