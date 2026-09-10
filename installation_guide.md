# LoreAuth installation guide (Team3)

Living guide for students and instructors. Updated as we install on the class Tailscale VM.

**Constraints (locked)**
- Free only (Tailscale free/personal plan)
- No public domain / paid IdP
- Do **not** patch LoreGUI, `lore`, or `loreserver`
- Students only need: Tailscale + LoreGUI + an access code

**Proven on**
- VM user: `team3`
- App dir: `~/LoreAuth`
- Data dir: `/opt/lore-auth/data`
- Tailnet: `tail1504a4.ts.net`
- MagicDNS host: `team3.tail1504a4.ts.net`
- Lore server: `lore://100.107.34.33:41337`
- Class repo name: `lore-test-project`

---

## 0. What you are installing

| Piece | Who runs it | Purpose |
|-------|-------------|---------|
| `lore-auth` server | Always-on on the Ubuntu VM | Login page + JWKS + UCS gRPC auth for LoreGUI |
| Admin menu | Instructor on the VM (or PC) | Add/disable student access codes |
| LoreGUI | Each student PC | Connect to Lore (stock app, no patches) |

---

## 1. Copy the project to the VM

From the instructor PC, copy at least:

- `proto/`
- `scripts/`
- `src/`
- `tests/`
- `requirements.txt`
- `pyproject.toml`

Onto the VM as `~/LoreAuth` (example path used in this guide).

Do **not** copy a Windows `.venv`.

---

## 2. Python install on the VM

```bash
cd ~/LoreAuth
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
pip install -e .
python scripts/gen_proto.py
```

---

## 3. Data directory permissions

```bash
sudo mkdir -p /opt/lore-auth/data
sudo chown -R "$USER:$USER" /opt/lore-auth/data
```

---

## 4. Init keys + empty users file (auto from Tailscale)

With venv active:

```bash
cd ~/LoreAuth
source .venv/bin/activate
python -m lore_auth.admin_cli init --auto
```

Expected: writes under `/opt/lore-auth/data/`:

- `users.json`
- `signing-private.pem`
- `signing-public.pem`
- `public-jwks.json`

Auto-detected values for Team3:

- issuer: `https://team3.tail1504a4.ts.net`
- audience: `team3.tail1504a4.ts.net,.tail1504a4.ts.net`
- env: `team3`

---

## 5. Admin menu (simplified)

```bash
cd ~/LoreAuth
source .venv/bin/activate
python -m lore_auth.menu --users /opt/lore-auth/data/users.json
```

On start, the menu **auto-runs Setup Lore** (no URL/hex typing):

- Queries `lore://100.107.34.33:41337`
- Saves class repo `lore-test-project` to `/opt/lore-auth/data/lore-setup.json`

Main menu:

1. Enter new user  
2. List users  
3. Disable user  
0. Quit  

### Add instructor admin (example)

1. Select `1`  
2. Select `2` (Admin)  
3. Username: `tomas`  
4. Save the printed **secret** (shown once)

---

## 6. Local smoke test (HTTP / --dev)

Terminal A:

```bash
cd ~/LoreAuth
source .venv/bin/activate
python -m lore_auth \
  --users /opt/lore-auth/data/users.json \
  --private-key /opt/lore-auth/data/signing-private.pem \
  --public-base-url http://127.0.0.1:8443 \
  --grpc-host 127.0.0.1 --grpc-port 50051 \
  --http-host 127.0.0.1 --http-port 8443 \
  --dev
```

Expected log: gRPC on `127.0.0.1:50051`, HTTP on `127.0.0.1:8443`.

Terminal B:

```bash
curl -s http://127.0.0.1:8443/.well-known/jwks.json
```

Expected: JSON with `"keys":[...]"kid":"..."` (RS256).

---

## 7. Tailscale HTTPS certificates (in progress)

### 7.1 Admin Console

1. Open https://login.tailscale.com/admin/dns  
2. Confirm **MagicDNS** is enabled  
3. Under **HTTPS Certificates**, click **Enable HTTPS...**  
4. Confirm the notice (names may appear in Certificate Transparency logs)

### 7.2 Request cert on the VM

```bash
sudo tailscale cert team3.tail1504a4.ts.net
```

**Status:** succeeded after enabling HTTPS Certificates in the Admin Console.

### 7.3 Install cert files (proven)

Run from the directory where `tailscale cert` wrote the files (often `~`):

```bash
cd ~
sudo mkdir -p /opt/lore-auth/certs
sudo mv ~/team3.tail1504a4.ts.net.crt /opt/lore-auth/certs/cert.pem
sudo mv ~/team3.tail1504a4.ts.net.key /opt/lore-auth/certs/key.pem
sudo chmod 600 /opt/lore-auth/certs/key.pem
sudo chown -R "$USER:$USER" /opt/lore-auth/certs
```

### 7.4 Stop the --dev server

In the terminal where `--dev` is running: press Ctrl+C.

---

## 8. Production lore-auth run (HTTPS) — TODO

After certs exist, stop `--dev` (`Ctrl+C`) and run with `--cert` / `--key` and:

- `--public-base-url https://team3.tail1504a4.ts.net`  
- gRPC TLS on port suitable for LoreGUI (`ucs-auth://team3.tail1504a4.ts.net` → HTTPS :443)

Details to be filled after the first successful HTTPS bring-up.

---

## 9. loreserver TOML — TODO

Required shape (fill hostnames after HTTPS works):

```toml
[environment.endpoint]
auth_url = "ucs-auth://team3.tail1504a4.ts.net"

[server.auth]
jwt_issuer = "https://team3.tail1504a4.ts.net"
jwt_audience = ["team3.tail1504a4.ts.net"]

[server.auth.jwk]
endpoint = "https://team3.tail1504a4.ts.net/.well-known/jwks.json"
```

*(JWKS URL port may need `:8443` until HTTP and gRPC share 443 via proxy — confirm in next install step.)*

---

## 10. Student connect flow (proven)

1. Install Tailscale and join the class tailnet (MagicDNS on).
2. Open LoreGUI → **Set Up Repository** → **Connect to a Lore Server** (not host).
3. Prefer **Open existing** / **Open Working Tree** if you already cloned; otherwise Clone with:
   `lore://<this-VM-MagicDNS>:41337/<repo-name>`
   Prefer MagicDNS over a bare Tailscale IP — JWT `aud` is MagicDNS-oriented.
4. Confirm the title bar is no longer `no repository open` and Branches shows `main`.
5. **Account** → Browser sign-in → Server URL:
   `lore://<this-VM-MagicDNS>:41337`
   Enter the access code. Success = green **Signed in (server-verified)**.
6. Commit normally. Do **not** put `identity = "..."` in `.lore/config.toml`.

If Account shows red `No auth endpoint available` before a repo is open, that can be a neutral empty state on older LoreGUI builds — open the working tree first, then Account.


---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `PermissionError` writing `/opt/lore-auth/data` | `sudo chown -R "$USER:$USER" /opt/lore-auth/data` |
| Menu asks for 32-hex repo id | Update `menu.py` / `setup_lore.py`; Setup Lore should auto-run |
| `tailscale cert` → account does not support TLS certs | Enable **HTTPS Certificates** on Admin DNS page |
| JWKS curl fails | Confirm `--dev` server still running; curl `127.0.0.1:8443` |

---

## Changelog

- 2026-09-09: Initial guide through JWKS smoke test.`r`n- 2026-09-09: Enabled Tailscale HTTPS Certificates; `tailscale cert team3.tail1504a4.ts.net` succeeded.

## Start server from the menu (preferred)

After users, signing keys, and Tailscale certs exist under `/opt/lore-auth/`, the menu shows:

`4. Start server`

Only appears when ready (users.json + signing key + cert.pem/key.pem + at least one user).

`ash
cd ~/LoreAuth
source .venv/bin/activate
python -m lore_auth.menu --users /opt/lore-auth/data/users.json
# Select 4
`

This starts HTTPS on `:8443` and gRPC TLS on `:50051` using issuer from `users.json`.
Stop with Ctrl+C.

## Student-simple flow (menu)

Students should **not** run raw `tailscale cert` / `mv` / long `python -m lore_auth ...` commands.

### Once per tailnet (instructor or first student with Admin rights)

1. Open https://login.tailscale.com/admin/dns
2. MagicDNS ON
3. Click **Enable HTTPS...** under HTTPS Certificates

### On each auth VM

```bash
cd ~/LoreAuth
source .venv/bin/activate
python -m lore_auth.menu --users /opt/lore-auth/data/users.json
```

Menu behavior:

- Auto-detects **this machine’s** MagicDNS name (not hardcoded `team3`)
- **Setup authentication server** — only while TLS certs are missing. Runs `tailscale cert <this-host>.<tailnet>.ts.net`, installs into `/opt/lore-auth/certs/`, then **disappears**
- **Start authentication server** — only when users + keys + certs are ready. Starts HTTPS `:8443` + gRPC TLS `:50051`
- Always: Enter / List / Disable user, Quit

## Proven loreserver TOML (team3 VM)

With lore-auth running (HTTPS `:8443`, gRPC TLS `:50051`):

```toml
[environment.endpoint]
auth_url = "ucs-auth://team3.tail1504a4.ts.net:50051"

[server.auth]
jwt_issuer = "https://team3.tail1504a4.ts.net"
jwt_audience = ["team3.tail1504a4.ts.net"]

[server.auth.jwk]
endpoint = "https://team3.tail1504a4.ts.net:8443/.well-known/jwks.json"
```

On other student VMs, replace `team3.tail1504a4.ts.net` with **that machine’s** MagicDNS name (menu/init --auto detects it).

Restart loreserver after editing. Keep lore-auth running.

## Setup writes loreserver-auth.toml

`Setup authentication server` now also writes:

`/opt/lore-auth/data/loreserver-auth.toml`

using **this machine's** MagicDNS name (not a hardcoded hostname). Merge/include that file into loreserver and restart loreserver. Setup stays visible until both TLS certs and this overlay exist; then **Start authentication server** appears.
## Background Start / Shut down (menu)

Both servers run in the **background**. The menu detects PIDs under `/opt/lore-auth/run/`:

- If authentication server is stopped → show **Start authentication server**
- If running → show **Shut down authentication server** (hide Start)
- Same pattern for **lore server**

Logs: `/opt/lore-auth/log/auth.log` and `lore.log`.

Setup authentication server also writes/merges `loreserver-auth.toml` using this machine's MagicDNS name.

## Account Connect (LoreGUI identity)

Open a working tree first (**Set Up Repository** → Connect → Open existing), then use **Account**.

1. Working-tree `remote_url` and Account Server URL should both use MagicDNS:
   `lore://<this-machine-MagicDNS>:41337`
2. Account → Browser sign-in → access code. Success = green **Signed in (server-verified)**.
3. Red `No auth endpoint available` with **no repository open** is often a loader quirk, not a failed login — open the repo, then retry Account.
4. JWT `aud` must cover the MagicDNS hostname (init/`--auto` sets MagicDNS + `.tailnet` + Tailscale IPs). Restart auth after updating lore-auth so new tokens pick up minting fixes.
5. Never hardcode a classmate hostname in student docs; each VM uses its own MagicDNS name.

