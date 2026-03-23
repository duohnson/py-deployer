## duohnson/hardening-debian-apt

Automates remote hardening of Debian/Ubuntu systems via Fabric, designed
specifically for hosts that use `apt-get`.

## Features

- Explicit support for Debian/Ubuntu (the `apt` package manager).
- Base hardening: system updates, `ufw`, `fail2ban`, and `sysctl` tweaks.
- Extras: install and enable Docker, automatic updates (`unattended-upgrades`), and auditing with Lynis.
- SSH credentials encrypted with `Fernet` and stored in a locally importable module.

## Structure

- `fabfile.py`: Fabric tasks (`bootstrap-credentials`, `harden`).
- `scripts/secure_credentials.py`: generated module with encrypted credentials.
- `scripts/hardener/credentials.py`: encryption/decryption utilities.
- `scripts/hardener/distro.py`: Debian/Ubuntu validation and `apt-get` existence checks.
- `scripts/hardener/hardening.py`: concrete hardening actions for `apt`.
- `scripts/customs.py`: custom commands executed automatically at the end of `harden`.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

1) Generate encrypted credentials (local):

```bash
# Prompts for the SSH user's password (for example: root)
fab bootstrap-credentials --username=root
```

## ATTENTION, IF USING UBUNTU SERVER:

Ubuntu Server ships with root login disabled by default. Use:

```bash
sudo nano /etc/ssh/sshd_config
PermitRootLogin yes
sudo systemctl restart ssh
```

This will generate:

- `.hardener.key` (local key — do not commit to git).
- `scripts/secure_credentials.py` (module with the encrypted password).

If `bootstrap-credentials` is not run manually, the `harden` task will perform
the bootstrap automatically the first time credentials are missing.

2) Run the remote hardening:

```bash
fab -H <IP_OR_HOST>
```

During execution you will be prompted for:
- The name of the superuser to create on the host.
- The superuser's password (with confirmation).
(I use this to create a custom admin user)

Also available:

```bash
fab -H <IP_OR_HOST> harden
fab -H <IP_OR_HOST> config
```

Example flags:

```bash
fab -H <IP_OR_HOST> harden --run-lynis=false --install-docker=true --enable-auto-updates=true
```

Non-interactive mode (no superuser prompt):

```bash
fab -H <IP_OR_HOST> harden --prompt-superuser=false --admin-username=adminops --admin-password='YourSecurePassword'
```

## Custom commands

You can add functions in `scripts/customs.py` to run extra commands
automatically at the end of `harden`.

Rules:

- Function name: must start with `cmd_`.
- Signature: `def cmd_something(conn):` or `def cmd_something(conn, context):`.
- They are executed in declaration order.

Example:

```python
def cmd_install_htop(conn):
	conn.sudo("DEBIAN_FRONTEND=noninteractive apt-get install -y htop", warn=True)
```

## Security

- Never store credentials in plain text.
- Keep `.hardener.key` out of repositories and public backups.
- For increased security, use SSH key authentication and disable password logins when possible.

This project only supports Debian/Ubuntu; if the remote host does not have `apt-get`, execution will deliberately abort.

Manual SSH hardening configuration:

```bash
sudo nano /etc/ssh/sshd_config
```
And add the following edits:

```bash
Port 2222
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
TCPKeepAlive no
LogLevel VERBOSE
ClientAliveCountMax 2
```

---

Questions or feedback? Find me on [GitHub](https://github.com/duohnson).

