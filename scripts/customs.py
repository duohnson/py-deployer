from inspect import signature

def _list_command_functions():
    command_functions = []
    for name, value in globals().items():
        if not name.startswith("cmd_"):
            continue
        if callable(value):
            command_functions.append((name, value))

    command_functions.sort(key=lambda item: item[1].__code__.co_firstlineno)
    return command_functions

def run_custom_commands(conn, context=None):
    executed = []
    errors = []

    for command_name, command_func in _list_command_functions():
        try:
            params = signature(command_func).parameters
            if len(params) >= 2:
                command_func(conn, context or {})
            else:
                command_func(conn)
            executed.append(command_name)
        except Exception as exc:
            errors.append({"command": command_name, "error": str(exc)})

    return {
        "executed": executed,
        "errors": errors,
    }
    
def cmd_install_clamav(conn):
    conn.sudo("DEBIAN_FRONTEND=noninteractive apt-get install -y clamav clamav-daemon", warn=True)
    conn.sudo("systemctl enable clamav-daemon", warn=True)
    conn.sudo("systemctl start clamav-daemon", warn=True)
    conn.sudo("freshclam", warn=True)

def cmd_install_rootkit_hunter(conn):
    conn.sudo("DEBIAN_FRONTEND=noninteractive apt-get install -y rkhunter", warn=True)
    conn.sudo("rkhunter --update", warn=True)
    conn.sudo("rkhunter --propupd", warn=True)
    conn.sudo("systemctl enable rkhunter.timer", warn=True)
    conn.sudo("systemctl start rkhunter.timer", warn=True)

def cmd_etc_sudoers(conn):
    conn.sudo(r"chmod 750 /etc/sudoers.d", warn=True)
    conn.sudo(r"chown root:root /etc/sudoers.d", warn=True)

def cmd_smtp_banner(conn):
    conn.sudo(r"postconf -e 'smtpd_banner = \$myhostname ESMTP'", warn=True)
    conn.sudo(r"postconf -e disable_vrfy_command=yes", warn=True)
    conn.sudo("systemctl restart postfix", warn=True)

def recomended_lynis_list(conn):
    conn.sudo("apt install -y apt-listbugs", warn=True)
    conn.sudo("apt install -y apt-listchanges", warn=True)
    conn.sudo("apt install -y libpam-tmpdir", warn=True)
    conn.sudo("apt install -y debsums", warn=True)
    conn.sudo("apt install -y apt-show-versions", warn=True)
    conn.sudo("apt install -y auditd", warn=True)
    conn.sudo("apt install -y aide", warn=True)
    conn.sudo("apt install -y sysstat", warn=True)
    conn.sudo("systemctl enable auditd", warn=True)
    conn.sudo("systemctl start auditd", warn=True)
    conn.sudo("systemctl enable aidecheck.timer", warn=True)
    conn.sudo("systemctl start aidecheck.timer", warn=True)
    conn.sudo("systemctl enable sysstat", warn=True)
    conn.sudo("systemctl start sysstat", warn=True)
    conn.sudo("aideinit", warn=True)
    conn.sudo("mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db", warn=True)

def cmd_hard_kernel(conn):
    config_text= (
        "install dccp /bin/true\n"
        "install sctp /bin/true\n"
        "install rds /bin/true\n"
        "install tipc /bin/true\n"
    )
    conn.sudo(f"echo '{config_text}' > /etc/modprobe.d/blacklist-protocols.conf", warn=True)

def cmd_configure_ssh_banner(conn):
    banner_text = "Authorized access only. All activity may be monitored and reported."
    conn.sudo(f"echo '{banner_text}' > /etc/issue.net", warn=True)
    conn.sudo(r"sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config", warn=True)
    conn.sudo("systemctl restart sshd", warn=True)

def cmd_copy_fail2ban(conn):
    conn.sudo(r"cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local", warn=True)
    conn.sudo("systemctl restart fail2ban", warn=True)

# Example:
# def cmd_install_htop(conn):
#     conn.sudo("DEBIAN_FRONTEND=noninteractive apt-get install -y htop", warn=True)
#
# def cmd_set_banner(conn):
#     conn.sudo("echo 'Authorized access only' > /etc/issue.net", warn=True)
