from dataclasses import dataclass

@dataclass
class DistroInfo:
    distro_id: str
    distro_name: str

def detect_distro(conn):
    distro_id = conn.run(
        "source /etc/os-release >/dev/null 2>&1 && echo ${ID:-unknown}",
        warn=True,
        hide=True,
    ).stdout.strip() or "unknown"
    distro_name = conn.run(
        "source /etc/os-release >/dev/null 2>&1 && echo ${PRETTY_NAME:-Linux}",
        warn=True,
        hide=True,
    ).stdout.strip() or "Linux"

    is_debian_family = conn.run(
        "source /etc/os-release >/dev/null 2>&1 && "
        "(echo ${ID:-} ${ID_LIKE:-} | grep -Eiq 'debian|ubuntu')",
        warn=True,
        hide=True,
    ).ok
    if not is_debian_family:
        raise RuntimeError(
            f"Unsupported distro for this project: {distro_name}. Use Debian/Ubuntu only."
        )

    if not conn.run("command -v apt-get", warn=True, hide=True).ok:
        raise RuntimeError("This project supports Debian/Ubuntu hosts only (apt-get not found)")

    return DistroInfo(
        distro_id=distro_id,
        distro_name=distro_name,
    )
