#!/usr/bin/env python3
"""Repeatable deployment of a dedicated loopback sshd and sharedfs-ssh bridge.

The client can optionally update ~/.ssh/config. Server deployment requires root;
--dry-run performs read-only checks and prints the intended configuration.
"""
import argparse
import base64
import fcntl
import grp
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = 1
MARKER = "# Managed by sharedfs-ssh deploy.py"
BLOCK_BEGIN = "# BEGIN sharedfs-ssh managed hosts"
BLOCK_END = "# END sharedfs-ssh managed hosts"
NODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
USER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")
KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
             "sk-ecdsa-sha2-nistp256@openssh.com"}
STOP = False


class DeployError(Exception):
    pass


def executable(name):
    path = shutil.which(name)
    if not path:
        raise DeployError("Missing %s; install it with your administrator/package manager first" % name)
    return str(Path(path).resolve())


def run(argv, **kwargs):
    result = subprocess.run([str(x) for x in argv], capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise DeployError("%s failed: %s" % (argv[0], (result.stderr or result.stdout).strip()))
    return result.stdout.strip()


def path_value(value):
    text = os.path.abspath(os.path.expanduser(str(value)))
    if any(ord(c) < 32 or c in '\x7f%$`"\'\\' for c in text):
        raise DeployError("Path contains unsupported control/config substitution characters: %r" % text)
    return Path(text)


def within(path, root):
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def validate_local_path(path, owner=None):
    """Reject symlink traversal and writable/untrusted installed-code ancestors."""
    owner = os.geteuid() if owner is None else owner
    for part in reversed([path, *path.parents]):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise DeployError("Local installation path contains a symlink: " + str(part))
        if info.st_uid not in (0, owner):
            raise DeployError("Local installation path has an untrusted owner: " + str(part))
        if info.st_mode & 0o022:
            raise DeployError("Local installation path/ancestor is group/world writable: " + str(part))


def reject_shared(path, shared):
    if within(path, shared):
        raise DeployError("Local state, executable files, and private keys must be outside the shared root")


def atomic_write(path, content, mode=0o600):
    if path.is_symlink():
        raise DeployError("Refusing symlink destination: " + str(path))
    data = content.encode() if isinstance(content, str) else content
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def create_directories(path, mode):
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=mode)
        os.chmod(directory, mode)  # Only directories created by this invocation.


def read_json(path, default=None):
    if path.is_symlink():
        raise DeployError("Refusing symlink metadata: " + str(path))
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default
    except (ValueError, UnicodeError) as exc:
        raise DeployError("Invalid deployment metadata: " + str(path)) from exc


def validate_public_key(path):
    content = Path(path).read_text().strip()
    if "PRIVATE KEY" in content:
        raise DeployError("A public key is required; refusing private-key input")
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 1:
        raise DeployError("Provide exactly one OpenSSH public-key line")
    parts = lines[0].split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise DeployError("Unsupported public key, or authorized_keys options were supplied")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        length = struct.unpack(">I", blob[:4])[0]
        if blob[4:4 + length].decode() != parts[0] or len(blob) <= 4 + length:
            raise ValueError("invalid SSH key encoding")
    except (ValueError, UnicodeError, struct.error) as exc:
        raise DeployError("Malformed SSH public key") from exc
    run([executable("ssh-keygen"), "-l", "-f", str(path)])
    return " ".join(parts[:2])


def ensure_host_key(state_dir, ssh_keygen=None):
    state_dir = Path(state_dir)
    binary = ssh_keygen or executable("ssh-keygen")
    private = state_dir / "ssh_host_ed25519_key"
    public = state_dir / "ssh_host_ed25519_key.pub"
    if private.is_symlink() or public.is_symlink():
        raise DeployError("Refusing symlink host-key files")
    if not private.exists():
        if public.exists():
            raise DeployError("Host public key exists without private key; restore the original private key")
        temporary = state_dir / (".host-key-" + uuid.uuid4().hex)
        try:
            run([binary, "-q", "-t", "ed25519", "-N", "", "-f", temporary])
            os.replace(temporary, private)
            os.replace(Path(str(temporary) + ".pub"), public)
        finally:
            temporary.unlink(missing_ok=True)
            Path(str(temporary) + ".pub").unlink(missing_ok=True)
    if private.stat().st_mode & 0o077:
        raise DeployError("Existing host private key must have mode 0600 or stricter")
    derived = run([binary, "-y", "-P", "", "-f", private])
    if public.exists() and validate_public_key(public) != " ".join(derived.split()[:2]):
        raise DeployError("Existing host public/private keys disagree; refusing to replace identity")
    if not public.exists():
        atomic_write(public, derived + "\n", 0o644)
    fingerprint = run([binary, "-l", "-f", public])
    return private, public, fingerprint


def append_authorized_key(path, key):
    if path.is_symlink():
        raise DeployError("Refusing symlink authorized_keys")
    existing = path.read_text() if path.exists() else ""
    wanted = key.split()[:2]
    found = False
    for line in existing.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        index = 0 if parts and parts[0] in KEY_TYPES else 1
        found = found or parts[index:index + 2] == wanted
    if not found:
        atomic_write(path, existing.rstrip("\n") + ("\n" if existing else "") + key + "\n", 0o644)
    return not found


def quote_config(path):
    return '"' + str(path) + '"'


def render_sshd_config(state_dir, login_user, port, use_pam):
    state = Path(state_dir)
    return "\n".join([
        # Older sshd versions require AddressFamily before ListenAddress.
        MARKER, "Port %d" % port, "AddressFamily inet", "ListenAddress 127.0.0.1",
        "HostKey " + quote_config(state / "ssh_host_ed25519_key"),
        "PidFile " + quote_config(state / "sshd.pid"),
        "AuthorizedKeysFile " + quote_config(state / "authorized_keys"),
        "AllowUsers " + login_user, "StrictModes yes", "PubkeyAuthentication yes",
        "AuthenticationMethods publickey", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PermitEmptyPasswords no",
        # The legacy spelling also works on sshd versions that predate prohibit-password.
        "PermitRootLogin without-password", "UsePAM " + use_pam, "UseDNS no",
        "PermitUserEnvironment no", "X11Forwarding no", "GatewayPorts no",
        "LoginGraceTime 120", "MaxAuthTries 3", "LogLevel VERBOSE",
        "Subsystem sftp internal-sftp", "",
    ])


def detect_pam(args, sshd):
    if args.pam != "auto":
        return args.pam
    result = subprocess.run([sshd, "-T"], capture_output=True, text=True)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if line.startswith("usepam "):
                return line.split()[1]
    # Query distro/global configuration without relying on usable system host keys.
    def scan(path, seen):
        if path in seen or len(seen) > 64 or not path.is_file():
            return None
        seen.add(path)
        for line in path.read_text().splitlines():
            words = shlex.split(line, comments=True)
            if not words:
                continue
            if words[0].lower() == "match":
                return None
            if words[0].lower() == "usepam" and len(words) == 2 and words[1].lower() in ("yes", "no"):
                return words[1].lower()
            if words[0].lower() == "include":
                import glob
                for pattern in words[1:]:
                    pattern = pattern if os.path.isabs(pattern) else "/etc/ssh/" + pattern
                    for included in sorted(glob.glob(pattern)):
                        value = scan(Path(included), seen)
                        if value:
                            return value
        return None
    detected = scan(Path("/etc/ssh/sshd_config"), set())
    if detected:
        return detected
    raise DeployError("Cannot determine existing UsePAM; inspect server policy and pass --pam yes or --pam no. No account will be unlocked.")


def timing_args(args, server=False):
    result = ["--poll", str(args.poll), "--control-interval", str(args.control_interval),
              "--heartbeat", str(args.heartbeat), "--peer-timeout", str(args.peer_timeout),
              "--connect-timeout", str(args.connect_timeout), "--window", str(args.window),
              "--chunk-size", str(args.chunk_size)]
    if server:
        result += ["--scan-interval", str(args.scan_interval), "--max-sessions", str(args.max_sessions)]
    if args.group_share:
        result += ["--group-share"]
    return result


def systemd_available():
    return bool(shutil.which("systemctl") and Path("/run/systemd/system").is_dir()
                and subprocess.run(["systemctl", "show-environment"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL).returncode == 0)


def choose_manager(requested, previous=None):
    manager = requested
    if manager == "auto":
        manager = previous or ("systemd" if systemd_available() else "supervisor")
    if manager == "systemd" and not systemd_available():
        raise DeployError("A functioning systemd manager is unavailable; use --service-manager supervisor")
    return manager


def proc_identity(pid):
    try:
        raw = Path("/proc/%d/stat" % pid).read_text()
        # Field 22 is starttime; comm can contain spaces and parentheses.
        start = raw[raw.rfind(")") + 2:].split()[19]
        command = Path("/proc/%d/cmdline" % pid).read_bytes().split(b"\0")
        return start, [x.decode(errors="replace") for x in command if x]
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
        return None


def running_supervisor(state):
    record = read_json(state / "supervisor.json")
    if not record:
        return None
    actual = proc_identity(record.get("pid", -1))
    expected = [str(state / "deploy.py"), "_supervise", "--state-dir", str(state)]
    if (actual and actual[0] == record.get("start") and actual[1][-4:] == expected):
        return record["pid"]
    return None


def load_deployment(state):
    validate_local_path(state, owner=0)
    validate_local_path(state / "deployment.json", owner=0)
    manifest = read_json(state / "deployment.json")
    if not manifest or manifest.get("version") != VERSION or manifest.get("kind") != "server":
        raise DeployError("No managed server deployment in " + str(state))
    return manifest


def stop_supervisor(state):
    pid = running_supervisor(state)
    if not pid:
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if not running_supervisor(state):
            return
        time.sleep(0.1)
    raise DeployError("Supervisor did not stop cleanly; inspect logs. No unrelated process was killed.")


def start_supervisor(state):
    if running_supervisor(state):
        return
    manifest = load_deployment(state)
    with (state / "supervisor.log").open("ab") as stream:
        child = subprocess.Popen([manifest["python"], str(state / "deploy.py"), "_supervise",
                                  "--state-dir", str(state)], stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=stream, start_new_session=True, close_fds=True)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if running_supervisor(state):
            return
        if child.poll() is not None:
            raise DeployError("Supervisor exited; inspect " + str(state / "supervisor.log"))
        time.sleep(0.1)
    raise DeployError("Supervisor readiness timeout; inspect " + str(state / "supervisor.log"))


def supervise(state):
    global STOP
    manifest = load_deployment(state)
    lock = os.open(state / "supervisor.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise DeployError("Supervisor already running") from exc
    identity = proc_identity(os.getpid())
    atomic_write(state / "supervisor.json", json.dumps({"pid": os.getpid(), "start": identity[0]}))
    signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__("STOP", True))
    signal.signal(signal.SIGINT, lambda *_: globals().__setitem__("STOP", True))
    children, logs = {}, {}
    try:
        for role in ("sshd", "bridge"):
            logs[role] = (state / (role + ".log")).open("ab")
        while not STOP:
            for role in ("sshd", "bridge"):
                child = children.get(role)
                if child is None or child.poll() is not None:
                    if child is not None:
                        print("%s exited %s; restarting after backoff" % (role, child.returncode), flush=True)
                        time.sleep(2)
                        if STOP:
                            break
                    gid = manifest.get("share_gid") if role == "bridge" else None
                    children[role] = subprocess.Popen(manifest[role + "_cmd"], stdin=subprocess.DEVNULL,
                        stdout=logs[role], stderr=logs[role], start_new_session=True,
                        group=gid if gid is not None else None)
            time.sleep(0.2)
    finally:
        for child in children.values():
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for child in children.values():
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=3)
        for stream in logs.values():
            stream.close()
        (state / "supervisor.json").unlink(missing_ok=True)
        os.close(lock)


def unit_text(state, manifest, role):
    unit = [MARKER + "; state=" + str(state), "[Unit]", "Description=Shared filesystem SSH " + role,
            "After=network-online.target", "Wants=network-online.target"]
    if role == "bridge":
        unit += ["After=" + manifest["units"][0], "Requires=" + manifest["units"][0],
                 "RequiresMountsFor=" + quote_config(manifest["share_root"])]
    unit += ["", "[Service]", "Type=simple", "User=root", "UMask=0077",
             "ExecStart=" + " ".join(quote_config(x) for x in manifest[role + "_cmd"]),
             "Restart=on-failure", "RestartSec=2", "KillMode=control-group", "TimeoutStopSec=10"]
    if role == "bridge" and manifest.get("share_gid") is not None:
        unit.append("Group=" + str(manifest["share_gid"]))
    return "\n".join(unit + ["", "[Install]", "WantedBy=multi-user.target", ""])


def preflight_units(state, manifest):
    for name in manifest["units"]:
        target = Path("/etc/systemd/system") / name
        validate_local_path(target, owner=0)
        if target.exists() and not target.read_text().startswith(MARKER + "; state=" + str(state) + "\n"):
            raise DeployError("Refusing to overwrite an unrelated systemd unit: " + str(target))


def install_units(state, manifest):
    preflight_units(state, manifest)
    for role, name in zip(("sshd", "bridge"), manifest["units"]):
        target = Path("/etc/systemd/system") / name
        atomic_write(target, unit_text(state, manifest, role), 0o644)
    run([executable("systemctl"), "daemon-reload"])


def check_sshd_config(sshd, candidate):
    result = subprocess.run([sshd, "-t", "-f", str(candidate)], capture_output=True, text=True)
    if result.returncode and result.stderr.strip() == "Missing privilege separation directory: /run/sshd":
        runtime = Path("/run/sshd")
        validate_local_path(runtime, owner=0)
        if not runtime.exists():
            runtime.mkdir(mode=0o755)
            os.chmod(runtime, 0o755)
            os.chown(runtime, 0, 0)
        run([sshd, "-t", "-f", candidate])
    elif result.returncode:
        raise DeployError("sshd configuration check failed: " + result.stderr.strip())


def server(args):
    if sys.platform != "linux":
        raise DeployError("Server deployment currently supports Linux")
    if not args.dry_run and os.geteuid() != 0:
        raise DeployError("Server installation requires root; --dry-run performs read-only planning without root")
    state = path_value(args.state_dir or "/var/lib/sharedfs-ssh/" + args.node)
    share = path_value(args.share_root)
    if not share.is_dir():
        raise DeployError("Shared root must already exist and be mounted")
    reject_shared(state, share)
    validate_local_path(state, owner=os.geteuid() if args.dry_run else 0)
    validate_local_path(state / "deployment.json", owner=os.geteuid() if args.dry_run else 0)
    login = pwd.getpwnam(args.login_user)
    if any(within(state, forbidden) for forbidden in
           (Path("/etc/ssh"), Path(login.pw_dir) / ".ssh", Path.home() / ".ssh")):
        raise DeployError("Server state must not be inside /etc/ssh or a user's .ssh directory")
    if args.public_key:
        key = validate_public_key(path_value(args.public_key))
    else:
        validate_local_path(state / "authorized_keys", owner=os.geteuid() if args.dry_run else 0)
        if not (state / "authorized_keys").is_file():
            raise DeployError("Existing authorized_keys is missing; redeploy with --public-key")
        key = None
    sshd = str(path_value(executable("sshd")))
    python = str(path_value(Path(sys.executable).resolve()))
    local_owner = os.geteuid() if args.dry_run else 0
    python_owner = local_owner
    trusted_owner = args.trust_python_owner
    if trusted_owner is not None:
        try:
            python_owner = int(trusted_owner) if trusted_owner.isdecimal() else pwd.getpwnam(trusted_owner).pw_uid
        except KeyError as exc:
            raise DeployError("Unknown --trust-python-owner account: " + trusted_owner) from exc
    for name, binary, owner in (("sshd", sshd, local_owner), ("Python", python, python_owner)):
        try:
            reject_shared(Path(binary), share)
            validate_local_path(Path(binary), owner=owner)
        except DeployError as exc:
            raise DeployError("%s (%s): %s" % (name, binary, exc)) from exc
    executable("ssh-keygen")
    pam = detect_pam(args, sshd)
    previous = read_json(state / "deployment.json", {})
    if previous and (previous.get("version") != VERSION or previous.get("kind") != "server"
                     or previous.get("node") != args.node or previous.get("login_user") != args.login_user):
        raise DeployError("State directory belongs to another node/user; use its original identity or a new state directory")
    existing_config = state / "sshd_config"
    if existing_config.exists() and not existing_config.read_text().startswith(MARKER + "\n"):
        raise DeployError("Refusing to overwrite an unrelated sshd_config in the requested state directory")
    manager = choose_manager(args.service_manager, previous.get("manager"))
    if previous and previous.get("manager") != manager and previous.get("manager") != "none":
        raise DeployError("Existing deployment uses a different service manager; retain its manager or use a separate state directory after stopping the old service")
    gid = None
    if args.share_group:
        record = grp.getgrgid(int(args.share_group)) if args.share_group.isdecimal() else grp.getgrnam(args.share_group)
        gid, args.group_share = record.gr_gid, True
    source = Path(__file__).resolve().parent / "sharedfs_ssh.py"
    if not source.is_file():
        raise DeployError("Place deploy.py next to sharedfs_ssh.py")
    config = render_sshd_config(state, args.login_user, args.ssh_port, pam)
    manifest = {"version": VERSION, "kind": "server", "node": args.node, "login_user": args.login_user,
        "share_root": str(share), "state_dir": str(state), "manager": manager, "share_gid": gid,
        "python": python,
        "units": ["sharedfs-sshd-%s.service" % args.node, "sharedfs-bridge-%s.service" % args.node],
        "sshd_cmd": [sshd, "-D", "-e", "-f", str(state / "sshd_config")],
        "bridge_cmd": [python, str(state / "sharedfs_ssh.py"), "server", "--root", str(share),
                       "--node", args.node, "--ssh-port", str(args.ssh_port)] + timing_args(args, True)}
    if args.dry_run:
        print(json.dumps(manifest, indent=2))
        print("\n# Dedicated sshd_config (no files written):\n" + config)
        return
    if manager == "systemd":
        preflight_units(state, manifest)
    create_directories(state, 0o755)
    lock = os.open(state / "deploy.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        current = read_json(state / "deployment.json", {})
        if current and (current.get("node") != args.node or current.get("login_user") != args.login_user
                        or current.get("manager") not in ("none", manager)):
            raise DeployError("Deployment identity/manager changed while waiting for the install lock")
        for name in ("deploy.py", "sharedfs_ssh.py", "authorized_keys", "sshd_config", "deployment.json",
                     "sshd.log", "bridge.log", "supervisor.log", "supervisor.json", "supervisor.lock",
                     "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub"):
            validate_local_path(state / name, owner=0)
        private, public, fingerprint = ensure_host_key(state)
        # Non-root login users must traverse this root-owned directory and read
        # their public authorized keys; private key/config/log files remain 0600.
        os.chmod(state, 0o755)
        candidate = state / (".sshd_config-" + uuid.uuid4().hex)
        atomic_write(candidate, config)
        try:
            check_sshd_config(sshd, candidate)
            effective = run([sshd, "-T", "-f", candidate, "-C", "user=%s,host=localhost,addr=127.0.0.1" % args.login_user])
            for required in ("passwordauthentication no", "pubkeyauthentication yes", "authenticationmethods publickey"):
                if required not in effective.splitlines():
                    raise DeployError("Dedicated sshd did not retain required policy: " + required)
            if key is not None:
                append_authorized_key(state / "authorized_keys", key)
            os.chmod(state / "authorized_keys", 0o644)
            os.replace(candidate, state / "sshd_config")
        finally:
            candidate.unlink(missing_ok=True)
        atomic_write(state / "sharedfs_ssh.py", source.read_bytes(), 0o644)
        atomic_write(state / "deploy.py", Path(__file__).read_bytes(), 0o644)
        atomic_write(state / "deployment.json", json.dumps(manifest, indent=2) + "\n")
        if manager == "systemd":
            install_units(state, manifest)
            run([executable("systemctl"), "enable", *manifest["units"]])
            run([executable("systemctl"), "restart", *manifest["units"]])
        elif manager == "supervisor":
            stop_supervisor(state)
            start_supervisor(state)
        print("Server deployment: " + str(state))
        print("Host public key: " + str(public))
        print("Verify this fingerprint through a trusted console: " + fingerprint)
        print("Service manager: " + manager)
        if manager in ("supervisor", "foreground"):
            print("No boot persistence in this mode; use the start command after a container/host restart.")
            print("Supervisor launched; inspect status and sshd.log/bridge.log for child startup failures.")
    finally:
        os.close(lock)
    if manager == "foreground":
        sys.stdout.flush()
        os.execv(python, [python, str(state / "deploy.py"), "_supervise", "--state-dir", str(state)])


def render_client_config(profiles, config_dir, bridge, python):
    lines = [MARKER]
    for node, item in sorted(profiles.items()):
        command = [python, str(bridge), "client", "--root", item["share_root"], "--node", node] + item["transport_args"]
        lines += ["", "Host " + node, "    HostName " + node, "    User " + item["login_user"],
            "    IdentityFile " + quote_config(item["identity_file"]), "    IdentitiesOnly yes",
            "    HostKeyAlias sharedfs-ssh-" + node,
            "    UserKnownHostsFile " + quote_config(config_dir / "known_hosts"),
            "    GlobalKnownHostsFile /dev/null",
            "    StrictHostKeyChecking " + ("yes" if item.get("host_key") else "ask"),
            "    ConnectTimeout " + str(int(item["connect_timeout"])),
            "    ServerAliveInterval 30", "    ServerAliveCountMax 4", "    ForwardAgent no",
            "    ProxyCommand " + shlex.join(command)]
    return "\n".join(lines) + "\n"


def merge_default_config(existing, config, previous_config=None):
    """Put managed hosts first so their options take precedence over Host * entries."""
    lines = existing.splitlines(keepends=True)
    markers = [(i, line.strip(" \t\r\n")) for i, line in enumerate(lines)
               if line.strip(" \t\r\n") in (BLOCK_BEGIN, BLOCK_END)]
    boundaries = [marker for _, marker in markers]
    reset = "\nHost *\n"
    if boundaries == [BLOCK_BEGIN, BLOCK_END] * (len(markers) // 2):
        blocks = [(markers[i][0], markers[i + 1][0] + 1) for i in range(0, len(markers), 2)]
    else:
        blocks = []
        # With one missing marker, remove only a body we can reconstruct exactly.
        if len(markers) == 1 and previous_config is not None:
            index, marker = markers[0]
            body = (previous_config + reset).splitlines()
            if marker == BLOCK_BEGIN:
                start, end = index, index + 1 + len(body)
                candidate = lines[start + 1:end]
            else:
                start, end = index - len(body), index + 1
                candidate = lines[max(0, start):index]
            if [line.rstrip("\r\n") for line in candidate] == body:
                blocks = [(start, end)]
        if not blocks:
            locations = ", ".join("%s at line %d" % ("BEGIN" if marker == BLOCK_BEGIN else "END", i + 1)
                                  for i, marker in markers)
            raise DeployError("Cannot determine sharedfs-ssh block boundaries in ~/.ssh/config (%s). "
                              "Check the BEGIN/END marker lines and rerun." % locations)
    unmanaged = []
    offset = 0
    for start, end in blocks:
        unmanaged.extend(lines[offset:start])
        offset = end
    unmanaged.extend(lines[offset:])
    block = BLOCK_BEGIN + "\n" + config + reset + BLOCK_END + "\n"
    return block + "".join(unmanaged)


def client(args):
    config_dir = path_value(args.config_dir or "~/.config/sharedfs-ssh")
    bin_dir = path_value(args.bin_dir or "~/.local/bin")
    share, identity = path_value(args.share_root), path_value(args.identity_file)
    if not share.is_dir() or not identity.is_file():
        raise DeployError("Shared root and local identity file must already exist")
    reject_shared(identity, share)
    for output in (config_dir, bin_dir, bin_dir / "dssh"):
        reject_shared(output, share)
        validate_local_path(output)
    if identity.stat().st_mode & 0o077:
        raise DeployError("Identity private key permissions must be 0600 or stricter; adjust the local key permissions explicitly")
    if "PRIVATE KEY" not in identity.read_text():
        raise DeployError("--identity-file must point to a local SSH private key")
    ssh, python = executable("ssh"), str(path_value(Path(sys.executable).resolve()))
    reject_shared(Path(python), share)
    validate_local_path(Path(python))
    bridge_source = Path(__file__).resolve().parent / "sharedfs_ssh.py"
    if not bridge_source.is_file():
        raise DeployError("Place deploy.py next to sharedfs_ssh.py")
    for name in ("profiles.json", "ssh_config", "known_hosts", "sharedfs_ssh.py"):
        validate_local_path(config_dir / name)
    profiles = read_json(config_dir / "profiles.json", {})
    old = profiles.get(args.node, {})
    host_key = validate_public_key(path_value(args.host_public_key)) if args.host_public_key else old.get("host_key")
    if args.host_public_key:
        fingerprint = run([executable("ssh-keygen"), "-l", "-E", "sha256", "-f", path_value(args.host_public_key)]).split()[1]
        if not args.host_fingerprint or fingerprint != args.host_fingerprint.rstrip("="):
            raise DeployError("Host fingerprint mismatch/missing: pass --host-fingerprint SHA256:... verified through the server's trusted console")
    if old.get("host_key") and host_key != old["host_key"]:
        raise DeployError("Pinned host key changed; verify server identity and update the profile deliberately")
    default_config = path_value("~/.ssh/config") if args.use_default_ssh_config else None
    bridge = config_dir / "sharedfs_ssh.py"
    previous_config = render_client_config(profiles, config_dir, bridge, python) if default_config and profiles else None
    profiles[args.node] = {"login_user": args.login_user, "share_root": str(share), "identity_file": str(identity),
        "host_key": host_key, "transport_args": timing_args(args), "connect_timeout": args.connect_timeout}
    config = render_client_config(profiles, config_dir, bridge, python)
    target_config = default_config or config_dir / "ssh_config"
    if default_config:
        reject_shared(default_config, share)
        validate_local_path(default_config)
        try:
            with default_config.open(newline="") as stream:
                existing = stream.read()
        except FileNotFoundError:
            existing = ""
        config = merge_default_config(existing, config, previous_config)
    wrapper_command = [ssh] if default_config else [ssh, "-F", str(target_config)]
    wrapper = "#!/bin/sh\n" + MARKER + "; config=" + str(config_dir) + "\nexec " + shlex.join(wrapper_command) + ' "$@"\n'
    targets = [(bin_dir / "dssh", "#!/bin/sh\n" + MARKER + "; config=" + str(config_dir) + "\n")]
    if not default_config:
        targets.append((target_config, MARKER))
    for target, header in targets:
        if target.exists() and not target.read_text().startswith(header):
            raise DeployError("Refusing to overwrite an unrelated file: " + str(target))
    if args.dry_run:
        print("# Will install wrapper: " + str(bin_dir / "dssh"))
        print("# Client config: " + str(target_config))
        print(config)
        return
    create_directories(config_dir, 0o700)
    create_directories(bin_dir, 0o755)
    if default_config:
        create_directories(default_config.parent, 0o700)
        validate_local_path(default_config)
    for name in ("profiles.json", "ssh_config", "known_hosts", "sharedfs_ssh.py"):
        validate_local_path(config_dir / name)
    known = (config_dir / "known_hosts").read_text() if (config_dir / "known_hosts").exists() else ""
    for node, profile in sorted(profiles.items()):
        if not profile.get("host_key"):
            continue
        alias = "sharedfs-ssh-" + node
        matches = []
        if (config_dir / "known_hosts").exists():
            lookup = subprocess.run([executable("ssh-keygen"), "-F", alias, "-f", str(config_dir / "known_hosts")],
                                    capture_output=True, text=True)
            if lookup.returncode not in (0, 1):
                raise DeployError("Cannot inspect existing known_hosts for " + node)
            matches = [line for line in lookup.stdout.splitlines() if line and not line.startswith("#")]
        for line in matches:
            parts = line.split()
            if len(parts) < 3 or parts[0].startswith("@") or " ".join(parts[1:3]) != profile["host_key"]:
                raise DeployError("Existing known_hosts conflicts with pinned key for " + node)
        entry = alias + " " + profile["host_key"]
        if not matches and entry not in known.splitlines():
            known = known.rstrip("\n") + ("\n" if known else "") + entry + "\n"
    atomic_write(config_dir / "known_hosts", known)
    atomic_write(config_dir / "profiles.json", json.dumps(profiles, indent=2) + "\n")
    atomic_write(target_config, config)
    atomic_write(config_dir / "sharedfs_ssh.py", bridge_source.read_bytes(), 0o644)
    atomic_write(bin_dir / "dssh", wrapper, 0o755)
    print("Client config: " + str(target_config))
    print("Run: " + shlex.join([str(bin_dir / "dssh"), args.node, "hostname"]))
    if not host_key:
        print("First connection will ASK about the host key; compare its fingerprint with the server's trusted console.")


def inspect_nodes(args):
    from sharedfs_ssh import BridgeError, diagnose, status

    try:
        return diagnose(args) if args.command == "diagnose" else status(args)
    except BridgeError as exc:
        raise DeployError(str(exc)) from exc


def lifecycle(args):
    if os.geteuid() != 0:
        raise DeployError("Server lifecycle commands require root")
    state = path_value(args.state_dir or "/var/lib/sharedfs-ssh/" + args.node)
    manifest = load_deployment(state)
    manager = manifest["manager"]
    if manager == "systemd":
        command = [executable("systemctl"), args.command, *manifest["units"]]
        if args.command == "status":
            command.append("--no-pager")
            subprocess.run(command, check=False)
        else:
            run(command)
    elif manager in ("supervisor", "foreground"):
        if args.command == "start":
            start_supervisor(state)
        elif args.command == "stop":
            stop_supervisor(state)
        else:
            print("Supervisor: " + (str(running_supervisor(state)) if running_supervisor(state) else "not running"))
            print("Logs: " + str(state))
    else:
        raise DeployError("Configuration-only deployment; rerun server with a chosen service-manager to start it")


def add_timing(parser, server_mode=False):
    parser.add_argument("--poll", type=float, default=0.1)
    parser.add_argument("--control-interval", type=float, default=1.0)
    parser.add_argument("--heartbeat", type=float, default=2.0)
    parser.add_argument("--peer-timeout", type=float, default=120.0)
    parser.add_argument("--connect-timeout", type=float, default=120.0)
    parser.add_argument("--window", type=int, default=32)
    parser.add_argument("--chunk-size", type=int, default=65536)
    parser.add_argument("--group-share", action="store_true")
    if server_mode:
        parser.add_argument("--scan-interval", type=float, default=0.25)
        parser.add_argument("--max-sessions", type=int, default=8)


def edit_server_args(edit, parser):
    """Reconstruct server options from the saved deployment, then apply overrides."""
    state = path_value(edit.state_dir or "/var/lib/sharedfs-ssh/" + edit.node)
    manifest = load_deployment(state)
    if edit.node and manifest.get("node") != edit.node:
        raise DeployError("Node does not match the saved deployment")
    if manifest.get("manager") == "foreground":
        raise DeployError("Edit cannot restart foreground mode; stop it and redeploy explicitly")
    if manifest.get("manager") == "none":
        raise DeployError("Configuration-only deployment has no service to restart; redeploy with a service manager")
    bridge = manifest.get("bridge_cmd", [])
    if len(bridge) < 4 or bridge[2] != "server":
        raise DeployError("Invalid saved bridge command")
    config_path = state / "sshd_config"
    validate_local_path(config_path, owner=0)
    config = config_path.read_text()
    if not config.startswith(MARKER + "\n"):
        raise DeployError("Refusing to use an unrelated sshd_config")
    pam = re.search(r"(?m)^UsePAM (yes|no)$", config)
    if not pam:
        raise DeployError("Cannot determine saved UsePAM setting")
    saved = ["server", "--node", manifest["node"], "--login-user", manifest["login_user"],
             "--state-dir", str(state), "--service-manager", manifest["manager"],
             "--pam", pam.group(1), "--public-key", "/unused"]
    bridge_options = bridge[3:]
    # The saved command has its own root and node; retain all its transport settings.
    for index in range(0, len(bridge_options)):
        option = bridge_options[index]
        if option == "--root":
            saved += ["--share-root", bridge_options[index + 1]]
        elif option == "--node":
            pass
        elif index and bridge_options[index - 1] in ("--root", "--node"):
            continue
        else:
            saved.append(option)
    if manifest.get("share_gid") is not None:
        saved += ["--share-group", str(manifest["share_gid"])]
    restored = parser.parse_args(saved)
    restored.public_key = None
    for name in ("share_root", "ssh_port", "pam", "share_group", "poll", "control_interval",
                 "heartbeat", "peer_timeout", "connect_timeout", "window", "chunk_size",
                 "group_share", "scan_interval", "max_sessions", "trust_python_owner"):
        value = getattr(edit, name, None)
        if value is not None:
            setattr(restored, name, value)
    restored.dry_run = edit.dry_run
    return restored


def main():
    if sys.version_info < (3, 9):
        print("deploy: Python 3.9 or newer is required (running %s). "
              "Use bash deploy.sh or pass --python /absolute/path/to/python3 to deploy.sh."
              % sys.version.split()[0], file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    server_parser = commands.add_parser("server")
    client_parser = commands.add_parser("client")
    nodes_parser = commands.add_parser("nodes", help="show node status on the shared filesystem")
    nodes_parser.add_argument("--share-root", dest="root", required=True)
    nodes_parser.add_argument("--max-age", type=float, default=10, metavar="SECONDS",
                              help="maximum heartbeat age in seconds (default: 10)")
    nodes_parser.add_argument("--details", action="store_true", help="show detailed states for all nodes")
    nodes_parser.add_argument("--node", help="show detailed state for one node")
    diagnose_parser = commands.add_parser("diagnose", help="watch a node for changing bridge boot IDs")
    diagnose_parser.add_argument("--share-root", dest="root", required=True)
    diagnose_parser.add_argument("--node", required=True)
    diagnose_parser.add_argument("--duration", type=float, default=30, help="observation time in seconds (default: 30)")
    diagnose_parser.add_argument("--interval", type=float, default=0.25, help="sampling interval in seconds (default: 0.25)")
    diagnose_parser.add_argument("--max-idle", type=float, default=10,
                                 help="maximum time in seconds without an observed update (default: 10)")
    for command in (server_parser, client_parser):
        command.add_argument("--share-root", required=True)
        command.add_argument("--node", required=True)
        command.add_argument("--login-user", default="root")
        command.add_argument("--dry-run", action="store_true")
    server_parser.add_argument("--public-key", required=True)
    server_parser.add_argument("--state-dir")
    server_parser.add_argument("--ssh-port", type=int, default=2222)
    server_parser.add_argument("--service-manager", choices=("auto", "systemd", "supervisor", "foreground", "none"), default="auto")
    server_parser.add_argument("--pam", choices=("auto", "yes", "no"), default="auto")
    server_parser.add_argument("--share-group")
    add_timing(server_parser, True)
    client_parser.add_argument("--identity-file", required=True)
    client_parser.add_argument("--host-public-key")
    client_parser.add_argument("--host-fingerprint", help="SHA256:... verified through a trusted server console; required with --host-public-key")
    client_parser.add_argument("--config-dir")
    client_parser.add_argument("--bin-dir")
    client_parser.add_argument("--use-default-ssh-config", action="store_true",
                               help="manage host entries in ~/.ssh/config for direct ssh access")
    add_timing(client_parser)
    edit_parser = commands.add_parser("edit", help="update a server node and restart its services")
    edit_parser.add_argument("--node")
    edit_parser.add_argument("--state-dir")
    edit_parser.add_argument("--dry-run", action="store_true")
    edit_parser.add_argument("--share-root")
    edit_parser.add_argument("--ssh-port", type=int)
    edit_parser.add_argument("--pam", choices=("auto", "yes", "no"))
    edit_parser.add_argument("--share-group")
    for name in ("poll", "control-interval", "heartbeat", "peer-timeout", "connect-timeout", "scan-interval"):
        edit_parser.add_argument("--" + name, type=float)
    for name in ("window", "chunk-size", "max-sessions"):
        edit_parser.add_argument("--" + name, type=int)
    edit_parser.add_argument("--group-share", action="store_true", default=None)
    for command in (server_parser, edit_parser):
        command.add_argument("--trust-python-owner", metavar="USER_OR_UID",
                             help="trust this additional owner for the server Python path and its ancestors")
    for name in ("start", "stop", "status", "_supervise"):
        command = commands.add_parser(name)
        command.add_argument("--state-dir")
        command.add_argument("--node")
    args = parser.parse_args()
    if getattr(args, "node", None) and (not NODE.fullmatch(args.node) or args.node in (".", "..")):
        parser.error("invalid node name")
    if args.command == "edit":
        if not args.node and not args.state_dir:
            parser.error("provide --node or --state-dir")
        try:
            args = edit_server_args(args, parser)
        except (DeployError, OSError, KeyError, ValueError, IndexError) as exc:
            print("deploy: " + str(exc), file=sys.stderr)
            return 1
    if hasattr(args, "login_user") and not USER.fullmatch(args.login_user):
        parser.error("invalid login user name")
    if args.command in ("server", "client"):
        if (not all(math.isfinite(x) for x in (args.poll, args.control_interval, args.heartbeat,
                                              args.peer_timeout, args.connect_timeout))
                or args.poll < 0.02 or args.control_interval < 0.02 or args.heartbeat <= 0
                or args.peer_timeout <= 2 * max(args.heartbeat, args.control_interval)
                or args.connect_timeout < 1 or not 1024 <= args.chunk_size <= 1048576
                or not 1 <= args.window <= 1024):
            parser.error("invalid timing/window: poll and control interval >=0.02; peer timeout >2*max(heartbeat, control interval)")
        if args.command == "server" and (not math.isfinite(args.scan_interval) or args.scan_interval < 0.02 or args.max_sessions < 1 or not 1 <= args.ssh_port <= 65535):
            parser.error("invalid scan interval, session limit, or port")
        if args.command == "client" and bool(args.host_public_key) != bool(args.host_fingerprint):
            parser.error("--host-public-key and --host-fingerprint must be provided together; otherwise omit both for first-connection ASK")
    elif args.command not in ("nodes", "diagnose") and not args.state_dir and not args.node:
        parser.error("provide --state-dir or --node")
    os.umask(0o077)
    try:
        if args.command == "server":
            server(args)
        elif args.command == "client":
            client(args)
        elif args.command in ("nodes", "diagnose"):
            return inspect_nodes(args)
        elif args.command == "_supervise":
            if os.geteuid() != 0:
                raise DeployError("Supervisor requires root")
            supervise(path_value(args.state_dir or "/var/lib/sharedfs-ssh/" + args.node))
        else:
            lifecycle(args)
        return 0
    except (DeployError, OSError, KeyError, ValueError) as exc:
        print("deploy: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
