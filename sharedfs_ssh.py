#!/usr/bin/env python3
"""SSH ProxyCommand over a trusted shared filesystem (POSIX, Python >= 3.9).

The bridge transports bytes to a fixed loopback sshd. SSH still authenticates,
encrypts, checks host keys, allocates terminals, and executes commands. This is
a reference transport, not a hardened multi-tenant message broker. Shared storage
must implement atomic same-directory rename and reasonably prompt visibility.
"""

import argparse
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import select
import signal
import socket
import sys
import tempfile
import threading
import time
import uuid

VERSION = "0.2.0"
PROTOCOL = 1
DEFAULT_MAX_AGE = 10
NODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
SESSION_RE = re.compile(r"[0-9a-f]{32}\Z")
STOP = threading.Event()


class BridgeError(Exception):
    pass


def log(message):
    print("sharedfs-ssh: " + str(message), file=sys.stderr, flush=True)


def publish(path, data):
    """Close a unique temporary file before an atomic same-directory rename."""
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def publish_json(path, data):
    publish(path, json.dumps(data, separators=(",", ":")).encode("utf-8"))


def read_bytes(path, maximum=16384):
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise BridgeError("oversized transport file: " + str(path))
        return data
    except FileNotFoundError:
        return None


def read_json(path):
    data = read_bytes(path)
    if data is None:
        return None
    try:
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("object required")
        return result
    except (ValueError, UnicodeDecodeError) as exc:
        raise BridgeError("invalid metadata: " + str(path)) from exc


def beat(path, **fields):
    publish_json(path, dict(fields, beat=uuid.uuid4().hex, time=time.time()))


def check_remote_error(session, peer):
    error = read_json(session / (peer + ".error"))
    if error is not None:
        raise BridgeError("peer: " + str(error.get("error", "transport failed")))


class Endpoint:
    """Two independently flow-controlled streams plus a heartbeat monitor."""

    def __init__(self, session, side, args, source, sink, boot, sock=None):
        self.session, self.side, self.args = session, side, args
        self.peer = "server" if side == "client" else "client"
        self.tx = session / ("c2s" if side == "client" else "s2c")
        self.rx = session / ("s2c" if side == "client" else "c2s")
        self.source, self.sink, self.sock, self.boot = source, sink, sock, boot
        self.stop = threading.Event()
        self.sent_done, self.received_done = threading.Event(), threading.Event()
        self.errors = queue.Queue()
        self.sent, self.acknowledged = 0, 0
        os.set_blocking(source, False)
        os.set_blocking(sink, False)

    def pause(self):
        if self.stop.wait(self.args.poll) or STOP.is_set():
            raise BridgeError("transport stopped")

    def get_ack(self):
        record = read_json(self.tx / "ack.json")
        if record is not None:
            number = record.get("next")
            if not isinstance(number, int) or not 0 <= number <= self.sent:
                raise BridgeError("invalid acknowledgement")
            self.acknowledged = max(self.acknowledged, number)
        return self.acknowledged

    def send_frame(self, payload):
        # Our cached acknowledgement is conservative. Refresh it only when
        # the window is full, rather than opening a shared file per packet.
        while self.sent - self.acknowledged >= self.args.window:
            if self.sent - self.get_ack() >= self.args.window:
                self.pause()
        if self.stop.is_set():
            raise BridgeError("transport stopped")
        publish(self.tx / ("%016d.pkt" % self.sent), payload)
        self.sent += 1

    def sender(self):
        while not self.stop.is_set():
            ready, _, _ = select.select([self.source], [], [], self.args.poll)
            if not ready:
                continue
            try:
                data = os.read(self.source, self.args.chunk_size)
            except BlockingIOError:
                continue
            self.send_frame(b"\x00" + data if data else b"\x01")
            if not data:
                # Retain the endpoint until the peer consumed our final EOF.
                while self.get_ack() < self.sent:
                    self.pause()
                self.sent_done.set()
                return

    def write_all(self, data):
        remaining = memoryview(data)
        while remaining:
            if self.stop.is_set() or STOP.is_set():
                raise BridgeError("transport stopped")
            _, ready, _ = select.select([], [self.sink], [], self.args.poll)
            if not ready:
                continue
            try:
                count = os.write(self.sink, remaining)
            except BlockingIOError:
                continue
            if count == 0:
                raise BridgeError("zero-byte output write")
            remaining = remaining[count:]

    def finish_output(self):
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError as exc:
                if exc.errno not in (errno.ENOTCONN, errno.EPIPE, errno.EBADF):
                    raise
        else:
            # Give ssh a true pipe EOF, even while stdin is still closing.
            os.close(self.sink)

    def receiver(self):
        sequence = 0
        while not self.stop.is_set():
            path = self.rx / ("%016d.pkt" % sequence)
            data = read_bytes(path, self.args.chunk_size + 1)
            if data is None:
                self.pause()
                continue
            if data[:1] == b"\x00" and len(data) > 1:
                self.write_all(data[1:])
                eof = False
            elif data == b"\x01":
                eof = True
            else:
                raise BridgeError("invalid data frame")
            sequence += 1
            publish_json(self.rx / "ack.json", {"next": sequence})
            path.unlink()
            if eof:
                # Publish EOF acknowledgement before closing stdout: ssh may
                # terminate its ProxyCommand immediately after seeing pipe EOF.
                self.finish_output()
                self.received_done.set()
                return

    def worker(self, function):
        try:
            function()
        except Exception as exc:
            self.errors.put(exc)
            self.stop.set()

    def run(self):
        workers = [threading.Thread(target=self.worker, args=(function,), daemon=True)
                   for function in (self.sender, self.receiver)]
        for worker in workers:
            worker.start()
        last_heartbeat, last_control, last_peer_change = 0.0, 0.0, time.monotonic()
        previous_peer = None
        try:
            while True:
                try:
                    error = self.errors.get_nowait()
                except queue.Empty:
                    error = None
                if error is not None:
                    raise error
                if self.sent_done.is_set() and self.received_done.is_set():
                    return
                if STOP.is_set():
                    raise BridgeError("interrupted")
                now = time.monotonic()
                if now - last_heartbeat >= self.args.heartbeat:
                    beat(self.session / (self.side + ".beat"))
                    last_heartbeat = now
                if now - last_control >= self.args.control_interval:
                    check_remote_error(self.session, self.peer)
                    current = read_bytes(self.session / (self.peer + ".beat"))
                    if current is not None and current != previous_peer:
                        previous_peer, last_peer_change = current, now
                    if now - last_peer_change > self.args.peer_timeout:
                        raise BridgeError("peer heartbeat expired; session cannot resume")
                    if self.side == "client":
                        server = read_json(self.session.parent.parent / "server.json")
                        if server is not None and server.get("boot") != self.boot:
                            raise BridgeError("server bridge restarted; open a new SSH session")
                    last_control = now
                # Local wakeups remain responsive to worker completion without
                # turning every data poll into several remote metadata reads.
                delay = min(self.args.poll,
                            self.args.heartbeat - (now - last_heartbeat),
                            self.args.control_interval - (now - last_control))
                self.stop.wait(max(0.0, delay))
        finally:
            self.stop.set()
            if self.sock is not None:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            for worker in workers:
                worker.join(timeout=0.5)


def record_error(session, side, exc):
    try:
        publish_json(session / (side + ".error"), {"error": str(exc)[:2000]})
    except OSError:
        pass


def node_directory(args):
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        raise BridgeError("shared --root must already exist and be mounted: " + str(root))
    if not NODE_RE.fullmatch(args.node) or args.node in (".", ".."):
        raise BridgeError("--node must be a simple name (letters, digits, _, -, .)")
    return root / args.node


def client(args):
    node = node_directory(args)
    deadline = time.monotonic() + args.connect_timeout
    server = None
    while server is None:
        if STOP.is_set() or time.monotonic() > deadline:
            raise BridgeError("no server bridge appeared before connect timeout")
        server = read_json(node / "server.json")
        if server is None:
            time.sleep(args.poll)
    if server.get("protocol") != PROTOCOL or not SESSION_RE.fullmatch(str(server.get("boot", ""))):
        raise BridgeError("incompatible server metadata")
    boot = server["boot"]
    session = node / "sessions" / uuid.uuid4().hex
    session.mkdir()
    (session / "c2s").mkdir()
    (session / "s2c").mkdir()
    beat(session / "client.beat")
    publish_json(session / "request.json", {"protocol": PROTOCOL, "boot": boot,
                                          "chunk_size": args.chunk_size})
    try:
        last_heartbeat, last_control = 0.0, 0.0
        while read_json(session / "accepted.json") is None:
            if STOP.is_set():
                raise BridgeError("interrupted")
            now = time.monotonic()
            if now > deadline:
                raise BridgeError("server did not accept before connect timeout")
            if now - last_control >= args.control_interval:
                check_remote_error(session, "server")
                current = read_json(node / "server.json")
                if current is not None and current.get("boot") != boot:
                    raise BridgeError("server bridge restarted during connection")
                last_control = now
            if now - last_heartbeat >= args.heartbeat:
                beat(session / "client.beat")
                last_heartbeat = now
            time.sleep(args.poll)
        Endpoint(session, "client", args, sys.stdin.fileno(), sys.stdout.fileno(), boot).run()
        publish_json(session / "client.done", {"ok": True})
        return 0
    except Exception as exc:
        record_error(session, "client", exc)
        raise


def acquire_local_lock(node, lock_dir):
    directory = Path(lock_dir).expanduser()
    if not directory.is_dir():
        raise BridgeError("--lock-dir must be an existing local directory")
    digest = hashlib.sha256(str(node).encode()).hexdigest()[:24]
    path = directory / ("sharedfs-ssh-%s-%s.lock" % (os.getuid(), digest))
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_nlink != 1:
            raise BridgeError("unsafe local lock file: " + str(path))
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise BridgeError("a bridge already serves this node on this host") from exc
    except Exception:
        os.close(fd)
        raise
    return fd


def serve_session(session, args, boot):
    sock = None
    try:
        request = read_json(session / "request.json")
        if request is None or request.get("boot") != boot:
            return
        if request.get("protocol") != PROTOCOL or request.get("chunk_size") != args.chunk_size:
            raise BridgeError("client/server protocol or --chunk-size mismatch")
        check_remote_error(session, "client")
        for directory in (session / "c2s", session / "s2c"):
            if not directory.is_dir() or directory.is_symlink():
                raise BridgeError("invalid session stream directory")
        sock = socket.create_connection(("127.0.0.1", args.ssh_port), timeout=args.connect_timeout)
        sock.setblocking(False)
        beat(session / "server.beat")
        publish_json(session / "accepted.json", {"boot": boot})
        Endpoint(session, "server", args, sock.fileno(), sock.fileno(), boot, sock).run()
        publish_json(session / "server.done", {"ok": True})
    except Exception as exc:
        record_error(session, "server", exc)
        log("session %s: %s" % (session.name, exc))
    finally:
        if sock is not None:
            sock.close()


def server(args):
    node = node_directory(args)
    lock_fd = acquire_local_lock(node, args.lock_dir)
    node.mkdir(exist_ok=True)
    sessions = node / "sessions"
    sessions.mkdir(exist_ok=True)
    boot = uuid.uuid4().hex
    active = {}
    retired = set()
    last_heartbeat, next_scan = 0.0, 0.0
    log("serving node %s -> 127.0.0.1:%d; boot %s" % (args.node, args.ssh_port, boot))
    try:
        while not STOP.is_set():
            now = time.monotonic()
            active = {name: worker for name, worker in active.items() if worker.is_alive()}
            if now - last_heartbeat >= args.heartbeat:
                beat(node / "server.json", protocol=PROTOCOL, boot=boot, node=args.node,
                     ssh_port=args.ssh_port, max_sessions=args.max_sessions, active_sessions=len(active))
                last_heartbeat = now
            if now >= next_scan and len(active) < args.max_sessions:
                for session in sessions.iterdir():
                    if len(active) >= args.max_sessions:
                        break
                    if (session.name in active or session.name in retired
                            or not SESSION_RE.fullmatch(session.name)
                            or session.is_symlink() or not session.is_dir()):
                        continue
                    if any((session / marker).exists() for marker in
                           ("server.done", "server.error", "client.error", "accepted.json")):
                        retired.add(session.name)
                        continue
                    try:
                        request = read_json(session / "request.json")
                        if request is None:
                            continue
                        if request.get("boot") != boot:
                            retired.add(session.name)
                            continue
                        worker = threading.Thread(target=serve_session,
                                                  args=(session, args, boot), daemon=True)
                        active[session.name] = worker
                        worker.start()
                    except (OSError, BridgeError) as exc:
                        log("ignoring session %s: %s" % (session.name, exc))
                # Immutable session IDs let us skip repeat per-file metadata
                # checks for retired sessions. Listing the directory is still
                # O(total retained sessions); offline cleanup remains needed.
                next_scan = time.monotonic() + args.scan_interval
            elif now >= next_scan:
                next_scan = now + args.scan_interval
            now = time.monotonic()
            delay = min(next_scan - now, args.heartbeat - (now - last_heartbeat))
            STOP.wait(max(0.0, delay))
    finally:
        STOP.set()
        deadline = time.monotonic() + 3
        for worker in active.values():
            worker.join(timeout=max(0, deadline - time.monotonic()))
        os.close(lock_fd)
    return 0


def read_node_heartbeat(node):
    heartbeat = node / "server.json"
    if heartbeat.is_symlink() or not heartbeat.is_file():
        return None
    metadata = read_json(heartbeat)
    if metadata is None:
        return None
    timestamp = float(metadata["time"])
    if not math.isfinite(timestamp) or timestamp <= 0:
        raise ValueError("invalid heartbeat timestamp")
    return metadata, timestamp


def heartbeat_status(node, metadata, age, max_age):
    if metadata.get("protocol") != PROTOCOL:
        return "UNKNOWN", "unsupported heartbeat protocol"
    boot, port = metadata.get("boot"), metadata.get("ssh_port")
    if (metadata.get("node") != node.name or not SESSION_RE.fullmatch(str(boot))
            or type(port) is not int or not 1 <= port <= 65535):
        return "UNKNOWN", "invalid node identity or loopback port"
    if age < -max_age:
        return "UNKNOWN", "heartbeat timestamp is ahead of client clock"
    if age > max_age:
        return "STALE", "heartbeat expired"
    return "ONLINE", "-"


def print_node_details(node, state, reason, metadata=None, timestamp=None, age=None):
    metadata = metadata or {}
    active, limit = metadata.get("active_sessions"), metadata.get("max_sessions")
    port, boot = metadata.get("ssh_port"), metadata.get("boot")
    seen = "-"
    if timestamp is not None:
        try:
            seen = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")
        except (OSError, OverflowError, ValueError):
            seen = "invalid timestamp"
    print(node.name, state, seen, "-" if age is None else "%.1f" % age,
          active if type(active) is int and active >= 0 else "-",
          limit if type(limit) is int and limit > 0 else "-",
          port if type(port) is int and 1 <= port <= 65535 else "-",
          boot if SESSION_RE.fullmatch(str(boot)) else "-", reason, sep="\t")


def status(args):
    details = args.details or args.node is not None
    max_age = args.max_age if args.max_age is not None else (DEFAULT_MAX_AGE if details else None)
    if max_age is not None and (not math.isfinite(max_age) or max_age <= 0):
        raise BridgeError("--max-age must be a positive finite number of seconds")
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        raise BridgeError("shared root is not a directory: " + str(root))
    if args.node is not None and (not NODE_RE.fullmatch(args.node) or args.node in (".", "..")):
        raise BridgeError("--node must be a simple name (letters, digits, _, -, .)")
    if details:
        print("NODE\tSTATUS\tLAST_HEARTBEAT_UTC\tAGE_S\tACTIVE_SESSIONS\tMAX_SESSIONS\tLOOPBACK_PORT\tBOOT\tDETAIL")
    else:
        print("NODE\tLAST_HEARTBEAT_AGE_S\tBOOT\tLOOPBACK_PORT")
    found = False
    nodes = [root / args.node] if args.node is not None else sorted(root.iterdir())
    for node in nodes:
        if (details or max_age is not None) and not NODE_RE.fullmatch(node.name):
            continue
        try:
            if node.is_symlink() or not node.is_dir():
                if args.node is not None:
                    print_node_details(node, "UNKNOWN", "node directory not found or is a symlink")
                    found = True
                continue
            record = read_node_heartbeat(node)
            if record is None:
                if details:
                    print_node_details(node, "UNKNOWN", "no readable heartbeat file")
                    found = True
                continue
        except (OSError, BridgeError, KeyError, ValueError, TypeError, OverflowError) as exc:
            if details:
                reason = "cannot read heartbeat" if isinstance(exc, OSError) else "invalid heartbeat metadata"
                print_node_details(node, "UNKNOWN", reason)
                found = True
            else:
                log("skipping node %s: %s" % (node.name, exc))
            continue
        metadata, timestamp = record
        age = time.time() - timestamp
        if max_age is not None:
            state, reason = heartbeat_status(node, metadata, age, max_age)
            if details:
                print_node_details(node, state, reason, metadata, timestamp, age)
                found = True
                continue
            if state != "ONLINE":
                continue
        boot, port = metadata.get("boot", "?"), metadata.get("ssh_port", "?")
        print("%s\t%.1f\t%s\t%s" % (node.name, max(0.0, age), boot, port))
        found = True
    if max_age is not None and not found:
        log("no node directories found" if details else "no live nodes found")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("client", "server"):
        command = sub.add_parser(name)
        command.add_argument("--root", required=True, help="already-mounted shared transport directory")
        command.add_argument("--node", required=True, help="unique server ID, e.g. gpu01")
        command.add_argument("--poll", type=float, default=0.1,
                             help="data/ack poll seconds (default: 0.1; minimum: 0.02)")
        command.add_argument("--control-interval", type=float, default=1.0,
                             help="peer heartbeat/error/restart check seconds (default: 1.0)")
        command.add_argument("--heartbeat", type=float, default=2.0, help="heartbeat interval in seconds")
        command.add_argument("--peer-timeout", type=float, default=120.0,
                             help="abort if peer heartbeat stops changing; seconds")
        command.add_argument("--connect-timeout", type=float, default=30.0,
                             help="maximum connection setup wait; seconds")
        command.add_argument("--chunk-size", type=int, default=65536,
                             help="maximum frame payload; must match on both ends")
        command.add_argument("--window", type=int, default=32,
                             help="maximum unacknowledged frames per outgoing stream")
        command.add_argument("--group-share", action="store_true",
                             help="umask 0007 instead of 0077; requires trusted shared group/ACLs")
        if name == "server":
            command.add_argument("--scan-interval", type=float, default=0.25,
                                 help="new-session directory scan seconds (default: 0.25)")
            command.add_argument("--ssh-port", type=int, default=22, help="fixed 127.0.0.1 sshd port")
            command.add_argument("--max-sessions", type=int, default=16)
            command.add_argument("--lock-dir", default=tempfile.gettempdir(),
                                 help="existing LOCAL directory for same-host single-daemon lock")
    command = sub.add_parser("status")
    command.add_argument("--root", required=True)
    command.add_argument("--max-age", type=float, metavar="SECONDS",
                         help="maximum heartbeat age for an online node, in seconds")
    command.add_argument("--details", action="store_true", help="show detailed states for all nodes")
    command.add_argument("--node", help="show detailed state for one node")
    args = parser.parse_args()
    if args.command != "status":
        timings = [args.poll, args.control_interval, args.heartbeat,
                   args.peer_timeout, args.connect_timeout]
        if not all(math.isfinite(value) for value in timings):
            parser.error("all timing values must be finite")
        if args.poll < 0.02 or args.control_interval < 0.02:
            parser.error("--poll and --control-interval must be at least 0.02 seconds")
        if (args.heartbeat <= 0 or args.connect_timeout <= 0
                or args.peer_timeout <= 2 * max(args.heartbeat, args.control_interval)):
            parser.error("positive heartbeat/connect timeout required; peer timeout must exceed "
                         "twice the heartbeat and control intervals")
        if not 1024 <= args.chunk_size <= 1048576 or not 1 <= args.window <= 1024:
            parser.error("invalid frame size or window")
        if args.command == "server" and (not 1 <= args.ssh_port <= 65535 or args.max_sessions < 1):
            parser.error("invalid ssh port or maximum sessions")
        if args.command == "server" and (not math.isfinite(args.scan_interval)
                                         or args.scan_interval < 0.02):
            parser.error("--scan-interval must be finite and at least 0.02 seconds")
        os.umask(0o007 if args.group_share else 0o077)
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: STOP.set())
    try:
        return {"client": client, "server": server, "status": status}[args.command](args)
    except (OSError, BridgeError, ValueError) as exc:
        log(exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
