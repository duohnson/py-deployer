import shlex
from io import StringIO

APT_NONINTERACTIVE_ENV = "DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a"
APT_COMMON_FLAGS = (
    "-o DPkg::Lock::Timeout=120 "
    "-o Dpkg::Use-Pty=0 "
    "-o Dpkg::Options::=--force-confdef "
    "-o Dpkg::Options::=--force-confold"
)

def _apt_sudo(conn, apt_args, warn=False):
    cmd = f"{APT_NONINTERACTIVE_ENV} apt-get {APT_COMMON_FLAGS} {apt_args}"
    return conn.sudo(cmd, warn=warn)

def update_system(conn):
    update_result = _apt_sudo(conn, "update -y", warn=True)
    upgrade_result = _apt_sudo(conn, "upgrade -y", warn=True)
    return update_result.ok and upgrade_result.ok

def install_packages(conn, packages):
    if not packages:
        return [], []

    cmd = f"install -y {' '.join(packages)}"

    result = _apt_sudo(conn, cmd, warn=True)
    if result.ok:
        return packages, []
    # if installation failed, try to identify which packages triggered the error
    failed = []
    for pkg in packages:
        if not _is_package_installed(conn, pkg):
            failed.append(pkg)
    installed = [p for p in packages if p not in failed]
    if failed:
        conn.run(f"echo 'Warning: some packages failed to install: {failed}'", warn=True)
    return installed, failed


def _is_package_installed(conn, package):
    return conn.run(f"dpkg -s {package}", warn=True, hide=True).ok

def configure_firewall(conn):
    if conn.run("command -v ufw", warn=True, hide=True).ok:
        conn.sudo("ufw --force reset")
        conn.sudo("ufw default deny incoming")
        conn.sudo("ufw default allow outgoing")
        conn.sudo("ufw allow 22/tcp")
        conn.sudo("ufw allow 80/tcp")
        conn.sudo("ufw allow 443/tcp")
        conn.sudo("ufw limit 22/tcp")
        conn.sudo("ufw --force enable")
        return "ufw"

    return "none"

def configure_fail2ban(conn):
    if not conn.run("systemctl list-unit-files | grep -q '^fail2ban.service'", warn=True, hide=True).ok:
        return False
    conn.sudo("systemctl enable --now fail2ban")
    return True

def configure_sysctl(conn):
    hardening_conf = """
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
""".strip()

    conn.sudo("cat > /etc/sysctl.d/99-hardening.conf << 'EOF'\n" + hardening_conf + "\nEOF")
    conn.sudo("sysctl --system")

def configure_auto_updates(conn):
    _apt_sudo(conn, "install -y unattended-upgrades", warn=True)
    conn.sudo("dpkg-reconfigure -f noninteractive unattended-upgrades")
    conn.sudo("cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\nEOF")
    return "unattended-upgrades"

def install_and_enable_docker(conn):
    installed, failed = install_packages(conn, ["docker.io"])
    if failed:
        return False
    if installed:
        conn.sudo("systemctl enable --now docker", warn=True)
    return conn.run("command -v docker", warn=True, hide=True).ok

def run_lynis(conn):
    if not conn.run("command -v lynis", warn=True, hide=True).ok:
        return False
    result = conn.sudo("lynis audit system --quick --no-colors", warn=True, timeout=1800)
    return result.ok

def create_superuser(conn, username, password):
    safe_username = shlex.quote(username)

    user_exists = conn.run(f"id -u {safe_username}", warn=True, hide=True).ok
    if not user_exists:
        conn.sudo(f"useradd -m -s /bin/bash {safe_username}", warn=True)

    # stdin for chpasswd to avoid shell escaping issues with special characters
    conn.sudo("chpasswd", in_stream=StringIO(f"{username}:{password}\n"), warn=True)

    if conn.run("getent group sudo", warn=True, hide=True).ok:
        conn.sudo(f"usermod -aG sudo {safe_username}", warn=True)
    elif conn.run("getent group wheel", warn=True, hide=True).ok:
        conn.sudo(f"usermod -aG wheel {safe_username}", warn=True)

    # basic lockout hardening to avoid stale password aging default
    conn.sudo(f"chage -M 90 -m 1 -W 7 {safe_username}", warn=True)
    created_ok = conn.run(f"id -u {safe_username}", warn=True, hide=True).ok

    return {
        "username": username,
        "created": not user_exists,
        "exists": created_ok,
    }

def run_hardening(
    conn,
    run_lynis_audit=True,
    install_docker=True,
    enable_auto_updates=True,
    superuser_name="",
    superuser_password="",
):
    packages = ["ufw", "fail2ban", "lynis", "curl", "ca-certificates"]

    errors = []

    update_ok = update_system(conn)
    if not update_ok:
        errors.append("apt_update_upgrade_failed")

    _, failed = install_packages(conn, packages)

    if failed:
        conn.run(f"echo 'Warning: could not install {failed}'", warn=True)
        errors.append(f"package_install_failed:{','.join(failed)}")

    superuser_result = None
    if superuser_name and superuser_password:
        try:
            superuser_result = create_superuser(conn, superuser_name, superuser_password)
        except Exception as exc:
            errors.append(f"superuser_failed:{exc}")

    try:
        firewall_backend = configure_firewall(conn)
    except Exception as exc:
        firewall_backend = "error"
        errors.append(f"firewall_failed:{exc}")

    try:
        fail2ban_enabled = configure_fail2ban(conn)
    except Exception as exc:
        fail2ban_enabled = False
        errors.append(f"fail2ban_failed:{exc}")

    try:
        configure_sysctl(conn)
    except Exception as exc:
        errors.append(f"sysctl_failed:{exc}")

    docker_installed = False
    if install_docker:
        try:
            docker_installed = install_and_enable_docker(conn)
        except Exception as exc:
            docker_installed = False
            errors.append(f"docker_failed:{exc}")

    auto_updates_backend = "disabled"
    if enable_auto_updates:
        try:
            auto_updates_backend = configure_auto_updates(conn)
        except Exception as exc:
            auto_updates_backend = "failed"
            errors.append(f"auto_updates_failed:{exc}")

    lynis_executed = False
    if run_lynis_audit:
        try:
            lynis_executed = run_lynis(conn)
        except Exception as exc:
            lynis_executed = False
            errors.append(f"lynis_failed:{exc}")

    return {
        "firewall": firewall_backend,
        "fail2ban": fail2ban_enabled,
        "docker": docker_installed,
        "auto_updates": auto_updates_backend,
        "lynis": lynis_executed,
        "superuser": superuser_result,
        "update_ok": update_ok,
        "errors": errors,
    }
