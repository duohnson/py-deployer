from getpass import getpass
from paramiko.ssh_exception import NoValidConnectionsError
from fabric import Connection, task
from scripts.hardener.credentials import (
    bootstrap_encrypted_credentials,
    load_connection_credentials,
)
from scripts.hardener.distro import detect_distro
from scripts.hardener.hardening import run_hardening
from scripts.customs import run_custom_commands


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}

def _collect_superuser_credentials(admin_username, admin_password, prompt_superuser):
    if admin_username and admin_password:
        return admin_username, admin_password

    if not _as_bool(prompt_superuser):
        return "", ""

    selected_username = (admin_username or input("Enter a user: ")).strip()
    if not selected_username:
        raise ValueError("Superuser name cannot be empty")

    selected_password = admin_password or getpass("Enter superuser password: ")
    confirm_password = getpass("Confirm superuser password: ")
    if selected_password != confirm_password:
        raise ValueError("Password confirmation does not match")
    if not selected_password:
        raise ValueError("Superuser password cannot be empty")

    return selected_username, selected_password


@task
def bootstrap_credentials(
    c,
    username="root",
    key_file=".hardener.key",
    module_file="scripts/secure_credentials.py",
):
    result = bootstrap_encrypted_credentials(
        username=username,
        key_file=key_file,
        module_file=module_file,
    )
    print("-Encrypted credentials generated successfully-")
    print(f"--> user: {result['username']}")
    print(f"--> key file: {result['key_file']}")
    print(f"--> credentials module: {result['module_file']}")


@task(default=True)
def harden(
    c,
    host="",
    port=22,
    key_file=".hardener.key",
    module_file="scripts/secure_credentials.py",
    username="root",
    bootstrap_if_missing=True,
    prompt_superuser=True,
    admin_username="",
    admin_password="",
    run_lynis=True,
    install_docker=True,
    enable_auto_updates=True,
):
    target_host = host or c.host
    if not target_host:
        raise ValueError("Target host is required. Use: fab -H <host> harden")

    try:
        connection_credentials = load_connection_credentials(key_file=key_file)
    except (FileNotFoundError, ValueError):
        if not _as_bool(bootstrap_if_missing):
            raise

        print("Encrypted credentials missing, bootstrapping now...")
        bootstrap_encrypted_credentials(
            username=username,
            key_file=key_file,
            module_file=module_file,
        )
        connection_credentials = load_connection_credentials(key_file=key_file)

    conn = Connection(host=target_host, port=int(port), **connection_credentials)

    try:
        conn.open()
    except NoValidConnectionsError as exc:
        raise RuntimeError(
            f"Unable to connect to {target_host}:{port} via SSH.\n"
            "Verify the host is online, SSH is running, and the port is correct.\n"
            f"Original error: {exc}"
        )
    except Exception as exc:
        raise RuntimeError(
            f"SSH connection/authentication failed for {target_host}:{port}.\n"
            "Check credentials, network reachability and SSH daemon settings.\n"
            f"Original error: {exc}"
        )

    print(f"Connected as: {connection_credentials.get('user')}")
    try:
        who = conn.run("whoami", hide=True)
        print(f"Remote whoami: {who.stdout.strip()}")
    except Exception:
        print("Warning: could not run whoami on remote host")

    sudo_check = conn.run("sudo -n true", warn=True, hide=True)
    if not sudo_check.ok:
        try:
            test = conn.sudo("echo SUDO_OK", warn=True, hide=True)
            if not test.ok:
                raise RuntimeError("Interactive sudo returned non-zero exit")
        except Exception as exc:
            raise RuntimeError(
                "Sudo password rejected or sudo not permitted for this user.\n"
                "Ensure the SSH user has sudo privileges, the correct password is stored, "
                "or switch to SSH key authentication. Original error: "
                f"{exc}"
            )

    distro = detect_distro(conn)
    print(f"Detected distro: {distro.distro_name} ({distro.distro_id})")

    superuser_name, superuser_password = _collect_superuser_credentials(
        admin_username=admin_username,
        admin_password=admin_password,
        prompt_superuser=prompt_superuser,
    )

    result = run_hardening(
        conn,
        run_lynis_audit=_as_bool(run_lynis),
        install_docker=_as_bool(install_docker),
        enable_auto_updates=_as_bool(enable_auto_updates),
        superuser_name=superuser_name,
        superuser_password=superuser_password,
    )

    custom_result = run_custom_commands(
        conn,
        context={
            "host": target_host,
            "distro": distro.distro_id,
            "hardening": result,
        },
    )

    print("Hardening completed")
    print(f"  System update/upgrade: {result.get('update_ok')}")
    print(f"  Firewall: {result['firewall']}")
    print(f"  Fail2Ban active: {result['fail2ban']}")
    print(f"  Docker installed: {result['docker']}")
    print(f"  Auto updates: {result['auto_updates']}")
    print(f"  Lynis executed: {result['lynis']}")
    if result["superuser"]:
        print(
            "  Superuser: "
            f"{result['superuser']['username']} "
            f"(created={result['superuser']['created']}, exists={result['superuser']['exists']})"
        )
    else:
        print("  Superuser: skipped")

    if result.get("errors"):
        print("  Errors:")
        for err in result["errors"]:
            print(f"    - {err}")
    else:
        print("  Errors: none")

    print(f"  Custom commands executed: {len(custom_result['executed'])}")
    if custom_result["executed"]:
        for cmd_name in custom_result["executed"]:
            print(f"    - {cmd_name}")

    if custom_result["errors"]:
        print("  Custom command errors:")
        for cmd_error in custom_result["errors"]:
            print(f"    - {cmd_error['command']}: {cmd_error['error']}")
    else:
        print("  Custom command errors: none")


@task
def config(c, **kwargs):
    return harden(c, **kwargs)
