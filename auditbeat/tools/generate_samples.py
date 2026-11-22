#!/usr/bin/env python3
"""Generate SYNTHETIC Auditbeat sample events for SOC-TA-auditbeat.

Every event written by this script is synthetic: hosts, users, IPs and hashes are
made up (IPs are RFC 5737 documentation ranges or RFC 1918). The *shape* of each
event follows the Auditbeat source code that builds it, so field names, nesting,
value types and event.action / event.category / event.type values match what
Auditbeat 8.19.x and 9.x actually ship:

  auditd          auditbeat/module/auditd/audit_linux.go + go-libaudit v2.6.2
                  aucoalesce/normalizations.yaml, cross-checked against the
                  auditd golden files in auditbeat/module/auditd/testdata
  file_integrity  auditbeat/module/file_integrity/{event.go,action.go}
  system/*        x-pack/auditbeat/module/system/{host,login,package,process,
                  socket,user}

Output: one NDJSON file per module/dataset in SOC-TA-auditbeat/samples/.
Usage:  python3 auditbeat/tools/generate_samples.py
"""

import json
import os
from datetime import datetime, timedelta, timezone

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SOC-TA-auditbeat", "samples")
BASE_TIME = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)

HOSTS = {
    "web-01": {
        "name": "web-01",
        "hostname": "web-01",
        "architecture": "x86_64",
        "os": {
            "type": "linux",
            "platform": "ubuntu",
            "name": "Ubuntu",
            "family": "debian",
            "version": "24.04.1 LTS (Noble Numbat)",
            "codename": "noble",
            "kernel": "6.8.0-47-generic",
        },
        "id": "8f0b2c7d4e6a4b1f9c3d2e1f0a9b8c7d",
        "containerized": False,
        "ip": ["10.20.1.15", "fe80::5054:ff:fe12:3456"],
        "mac": ["52-54-00-12-34-56"],
    },
    "db-01": {
        "name": "db-01",
        "hostname": "db-01",
        "architecture": "x86_64",
        "os": {
            "type": "linux",
            "platform": "rhel",
            "name": "Red Hat Enterprise Linux",
            "family": "redhat",
            "version": "9.4 (Plow)",
            "kernel": "5.14.0-427.13.1.el9_4.x86_64",
        },
        "id": "3c9e1a7b5d2f4e8a9b0c1d2e3f4a5b6c",
        "containerized": False,
        "ip": ["10.20.2.21", "fe80::5054:ff:fe65:4321"],
        "mac": ["52-54-00-65-43-21"],
    },
}

AGENT_IDS = {
    "web-01": ("0b6f2b5e-7c1d-4a8e-9f3a-2d1c0b9a8e7f", "5e4d3c2b-1a09-4f8e-b7d6-c5b4a3928170"),
    "db-01": ("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "9f8e7d6c-5b4a-4392-8171-6e5d4c3b2a19"),
}

_clock = [BASE_TIME]


def ts(step_seconds=7):
    _clock[0] += timedelta(seconds=step_seconds, milliseconds=137)
    return _clock[0].strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (_clock[0].microsecond // 1000)


def envelope(host, module, dataset=None):
    agent_id, ephemeral = AGENT_IDS[host]
    event = {"module": module}
    if dataset:
        # auditbeat/core/eventmod.go: event.dataset is omitted when module == metricset (auditd).
        event["dataset"] = dataset
    return {
        "@timestamp": ts(),
        "agent": {"type": "auditbeat", "version": "9.5.5", "name": host, "id": agent_id, "ephemeral_id": ephemeral},
        "ecs": {"version": "8.0.0"},
        "host": json.loads(json.dumps(HOSTS[host])),
        "service": {"type": module},
        "event": event,
    }


def merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)
        else:
            dst[k] = v
    return dst


# --------------------------------------------------------------------------- auditd

_seq = [48210]


def auditd(host, action, category, etype, outcome, message_type, body, session="7", result=None):
    _seq[0] += 3
    ev = envelope(host, "auditd")
    ev["event"].update({"kind": "event", "action": action, "outcome": outcome})
    if category is not None:
        ev["event"]["category"] = category
    if etype is not None:
        ev["event"]["type"] = etype
    ev["auditd"] = {
        "message_type": message_type,
        "sequence": _seq[0],
        "result": result or ("success" if outcome == "success" else "fail"),
    }
    if session is not None:
        ev["auditd"]["session"] = session
    return merge(ev, body)


def syscall_user(uid, uname, auid=None, auname=None, euid=None, euname=None):
    """user.* as built by addUser + ResolveIDs for SYSCALL records."""
    u = {
        "id": uid, "name": uname,
        "group": {"id": uid, "name": uname},
        "saved": {"id": uid, "name": uname, "group": {"id": uid, "name": uname}},
        "filesystem": {"id": uid, "name": uname, "group": {"id": uid, "name": uname}},
    }
    if auid:
        u["audit"] = {"id": auid, "name": auname}
    if euid and euid != uid:
        u["effective"] = {"id": euid, "name": euname, "group": {"id": euid, "name": euname}}
    return u


def gen_auditd():
    evs = []
    sshd_auth = {
        "process": {"executable": "/usr/sbin/sshd", "pid": 31877},
        "service": {"type": "auditd"},
    }

    # --- process execution (SYSCALL execve + EXECVE + CWD + PATH + PROCTITLE)
    evs.append(auditd("web-01", "executed", ["process"], ["start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "55d1c2a0b3f0", "a1": "55d1c2a0b5e0", "a2": "55d1c2a0b7c0", "a3": "8", "arch": "x86_64",
                     "argc": "3", "exit": "0", "syscall": "execve", "tty": "pts0"},
            "paths": [
                {"dev": "fd:00", "inode": "1835109", "item": "0", "mode": "0100755", "name": "/usr/bin/curl",
                 "nametype": "NORMAL", "ogid": "0", "ouid": "0", "rdev": "00:00"},
                {"dev": "fd:00", "inode": "1835007", "item": "1", "mode": "0100755", "name": "/lib64/ld-linux-x86-64.so.2",
                 "nametype": "NORMAL", "ogid": "0", "ouid": "0", "rdev": "00:00"},
            ],
            "summary": {"actor": {"primary": "alice", "secondary": "root"}, "how": "/usr/bin/curl",
                        "object": {"primary": "/usr/bin/curl", "type": "file"}},
        },
        "user": syscall_user("0", "root", "1001", "alice"),
        "process": {"pid": 24410, "parent": {"pid": 24391}, "name": "curl", "executable": "/usr/bin/curl",
                    "working_directory": "/root", "args": ["curl", "-fsSL", "https://downloads.example.com/agent.sh"],
                    "title": "curl -fsSL https://downloads.example.com/agent.sh"},
        "file": {"path": "/usr/bin/curl", "device": "00:00", "inode": "1835109", "mode": "0755", "uid": "0", "gid": "0",
                 "owner": "root", "group": "root"},
        "tags": ["exec"],
        "related": {"user": ["alice", "root"]},
    }, session="12"))

    evs.append(auditd("web-01", "executed", ["process"], ["start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "5620f1d3a2b0", "a1": "5620f1d3a5e0", "a2": "5620f1d3a7f0", "a3": "0", "arch": "x86_64",
                     "argc": "2", "exit": "0", "syscall": "execve", "tty": "pts1"},
            "paths": [{"dev": "fd:00", "inode": "1836221", "item": "0", "mode": "0100755", "name": "/usr/bin/whoami",
                       "nametype": "NORMAL", "ogid": "0", "ouid": "0", "rdev": "00:00"}],
            "summary": {"actor": {"primary": "bob", "secondary": "bob"}, "how": "/usr/bin/whoami",
                        "object": {"primary": "/usr/bin/whoami", "type": "file"}},
        },
        "user": syscall_user("1002", "bob", "1002", "bob"),
        "process": {"pid": 25102, "parent": {"pid": 25087}, "name": "whoami", "executable": "/usr/bin/whoami",
                    "working_directory": "/home/bob", "args": ["whoami", "--help"], "title": "whoami --help"},
        "file": {"path": "/usr/bin/whoami", "device": "00:00", "inode": "1836221", "mode": "0755", "uid": "0", "gid": "0",
                 "owner": "root", "group": "root"},
        "tags": ["exec"],
        "related": {"user": ["bob"]},
    }, session="14"))

    evs.append(auditd("db-01", "executed", ["process"], ["start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "7ffd3a1b2c00", "a1": "7ffd3a1b2d00", "a2": "7ffd3a1b2e00", "a3": "0", "arch": "x86_64",
                     "argc": "4", "exit": "0", "syscall": "execve", "tty": "(none)"},
            "paths": [{"dev": "fd:00", "inode": "4410923", "item": "0", "mode": "0100755", "name": "/usr/bin/pg_dump",
                       "nametype": "NORMAL", "ogid": "0", "ouid": "0", "rdev": "00:00"}],
            "summary": {"actor": {"primary": "unset", "secondary": "postgres"}, "how": "/usr/bin/pg_dump",
                        "object": {"primary": "/usr/bin/pg_dump", "type": "file"}},
        },
        "user": syscall_user("26", "postgres"),
        "process": {"pid": 88123, "parent": {"pid": 88110}, "name": "pg_dump", "executable": "/usr/bin/pg_dump",
                    "working_directory": "/var/lib/pgsql", "args": ["pg_dump", "-Fc", "-f", "/backup/app.dump"],
                    "title": "pg_dump -Fc -f /backup/app.dump"},
        "file": {"path": "/usr/bin/pg_dump", "device": "00:00", "inode": "4410923", "mode": "0755", "uid": "0", "gid": "0",
                 "owner": "root", "group": "root"},
        "tags": ["exec"],
        "related": {"user": ["postgres"]},
    }, session=None))

    # Root daemon exec without a login session (auid unset), from a systemd timer.
    # process.parent.name/executable/args are only present with the optional
    # add_process_metadata + rename processor recipe from the README.
    evs.append(auditd("db-01", "executed", ["process"], ["start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "55c3a1b2c0d0", "a1": "55c3a1b2c1e0", "a2": "55c3a1b2c2f0", "a3": "0", "arch": "x86_64",
                     "argc": "2", "exit": "0", "syscall": "execve", "tty": "(none)"},
            "paths": [{"dev": "fd:00", "inode": "4401188", "item": "0", "mode": "0100755", "name": "/usr/sbin/logrotate",
                       "nametype": "NORMAL", "ogid": "0", "ouid": "0", "rdev": "00:00"}],
            "summary": {"actor": {"primary": "unset", "secondary": "root"}, "how": "/usr/sbin/logrotate",
                        "object": {"primary": "/usr/sbin/logrotate", "type": "file"}},
        },
        "user": syscall_user("0", "root"),
        "process": {"pid": 91544, "name": "logrotate", "executable": "/usr/sbin/logrotate", "working_directory": "/",
                    "args": ["/usr/sbin/logrotate", "/etc/logrotate.conf"],
                    "title": "/usr/sbin/logrotate /etc/logrotate.conf",
                    "parent": {"pid": 1, "name": "systemd", "executable": "/usr/lib/systemd/systemd",
                               "args": ["/usr/lib/systemd/systemd", "--switched-root", "--system"]}},
        "file": {"path": "/usr/sbin/logrotate", "device": "00:00", "inode": "4401188", "mode": "0755", "uid": "0",
                 "gid": "0", "owner": "root", "group": "root"},
        "tags": ["exec"],
        "related": {"user": ["root"]},
    }, session=None))

    # --- sudo command (USER_CMD)
    evs.append(auditd("web-01", "ran-command", ["process"], ["start"], "success", "user_cmd", {
        "auditd": {
            "data": {"cmd": "systemctl restart nginx", "terminal": "pts/0"},
            "summary": {"actor": {"primary": "alice", "secondary": "alice"},
                        "object": {"primary": "systemctl restart nginx", "type": "process"}},
        },
        "process": {"pid": 24388, "working_directory": "/home/alice"},
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"}},
        "related": {"user": ["alice"]},
    }, session="12"))

    # --- network: connect / accept / bind / listen
    def sock_user(uid, name, auid=None, auname=None):
        u = syscall_user(uid, name, auid, auname)
        return u

    evs.append(auditd("web-01", "connected-to", ["network"], ["connection", "start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "5", "a1": "7ffc4a2b1c30", "a2": "10", "a3": "0", "arch": "x86_64", "exit": "0",
                     "syscall": "connect", "tty": "pts0",
                     "socket": {"addr": "198.51.100.20", "family": "ipv4", "port": "443"}},
            "summary": {"actor": {"primary": "alice", "secondary": "root"}, "how": "/usr/bin/curl",
                        "object": {"primary": "198.51.100.20", "secondary": "443", "type": "socket"}},
        },
        "user": sock_user("0", "root", "1001", "alice"),
        "process": {"pid": 24410, "parent": {"pid": 24391}, "name": "curl", "executable": "/usr/bin/curl",
                    "title": "curl -fsSL https://downloads.example.com/agent.sh"},
        "destination": {"ip": "198.51.100.20", "port": "443"},
        "network": {"direction": "egress"},
        "tags": ["net"],
        "related": {"user": ["alice", "root"]},
    }, session="12"))

    evs.append(auditd("web-01", "connected-to", ["network"], ["connection", "start"], "failure", "syscall", {
        "auditd": {
            "data": {"a0": "7", "a1": "7f1e2d3c4b50", "a2": "10", "a3": "4", "arch": "x86_64", "exit": "EINPROGRESS",
                     "syscall": "connect", "tty": "(none)",
                     "socket": {"addr": "198.51.100.45", "family": "ipv4", "port": "8443"}},
            "summary": {"actor": {"primary": "unset", "secondary": "www-data"}, "how": "/usr/bin/python3.12",
                        "object": {"primary": "198.51.100.45", "secondary": "8443", "type": "socket"}},
        },
        "user": sock_user("33", "www-data"),
        "process": {"pid": 19044, "parent": {"pid": 1}, "name": "gunicorn", "executable": "/usr/bin/python3.12",
                    "title": "/usr/bin/python3 /opt/app/venv/bin/gunicorn app:wsgi"},
        "destination": {"ip": "198.51.100.45", "port": "8443"},
        "network": {"direction": "egress"},
        "tags": ["net"],
        "related": {"user": ["www-data"]},
    }, session=None))

    evs.append(auditd("db-01", "connected-to", ["network"], ["connection", "start"], "failure", "syscall", {
        "auditd": {
            "data": {"a0": "3", "a1": "7ffe11223340", "a2": "10", "a3": "0", "arch": "x86_64", "exit": "ECONNREFUSED",
                     "syscall": "connect", "tty": "pts0",
                     "socket": {"addr": "10.20.2.30", "family": "ipv4", "port": "5432"}},
            "summary": {"actor": {"primary": "carol", "secondary": "carol"}, "how": "/usr/bin/psql",
                        "object": {"primary": "10.20.2.30", "secondary": "5432", "type": "socket"}},
        },
        "user": sock_user("1005", "carol", "1005", "carol"),
        "process": {"pid": 90211, "parent": {"pid": 90180}, "name": "psql", "executable": "/usr/bin/psql",
                    "title": "psql -h 10.20.2.30 -U app"},
        "destination": {"ip": "10.20.2.30", "port": "5432"},
        "network": {"direction": "egress"},
        "tags": ["net"],
        "related": {"user": ["carol"]},
    }, session="31"))

    evs.append(auditd("web-01", "connected-to", ["network"], ["connection", "start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "3", "a1": "7ffd9b8c7d60", "a2": "13", "a3": "0", "arch": "x86_64", "exit": "0",
                     "syscall": "connect", "tty": "pts0",
                     "socket": {"family": "unix", "path": "/run/systemd/private"}},
            "summary": {"actor": {"primary": "alice", "secondary": "root"}, "how": "/usr/bin/systemctl",
                        "object": {"primary": "/run/systemd/private", "type": "socket"}},
        },
        "user": sock_user("0", "root", "1001", "alice"),
        "process": {"pid": 24389, "parent": {"pid": 24388}, "name": "systemctl", "executable": "/usr/bin/systemctl",
                    "title": "systemctl restart nginx"},
        "network": {"direction": "egress"},
        "tags": ["net"],
        "related": {"user": ["alice", "root"]},
    }, session="12"))

    evs.append(auditd("web-01", "accepted-connection-from", ["network"], ["connection", "start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "3", "a1": "7ffd0dc80040", "a2": "7ffd0dc7ffd0", "a3": "0", "arch": "x86_64", "exit": "5",
                     "syscall": "accept", "tty": "(none)",
                     "socket": {"addr": "203.0.113.50", "family": "ipv4", "port": "51522"}},
            "summary": {"actor": {"primary": "unset", "secondary": "root"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "203.0.113.50", "secondary": "51522", "type": "socket"}},
        },
        "user": sock_user("0", "root"),
        "process": {"pid": 1102, "parent": {"pid": 1}, "name": "sshd", "executable": "/usr/sbin/sshd",
                    "title": "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"},
        "source": {"ip": "203.0.113.50", "port": "51522"},
        "network": {"direction": "ingress"},
        "tags": ["net"],
        "related": {"user": ["root"]},
    }, session=None))

    evs.append(auditd("web-01", "bound-socket", ["network"], ["start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "6", "a1": "55a0c1d2e3f0", "a2": "10", "a3": "0", "arch": "x86_64", "exit": "0",
                     "syscall": "bind", "tty": "(none)",
                     "socket": {"addr": "0.0.0.0", "family": "ipv4", "port": "8080"}},
            "summary": {"actor": {"primary": "unset", "secondary": "root"}, "how": "/usr/sbin/nginx",
                        "object": {"primary": "0.0.0.0", "secondary": "8080", "type": "socket"}},
        },
        "user": sock_user("0", "root"),
        "process": {"pid": 24395, "parent": {"pid": 1}, "name": "nginx", "executable": "/usr/sbin/nginx",
                    "title": "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"},
        "tags": ["net"],
        "related": {"user": ["root"]},
    }, session=None))

    evs.append(auditd("db-01", "bound-socket", ["network"], ["start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "3", "a1": "c000124a80", "a2": "1c", "a3": "0", "arch": "x86_64", "exit": "0",
                     "syscall": "bind", "tty": "(none)",
                     "socket": {"addr": "::", "family": "ipv6", "port": "9100"}},
            "summary": {"actor": {"primary": "unset", "secondary": "node_exporter"}, "how": "/usr/local/bin/node_exporter",
                        "object": {"primary": "::", "secondary": "9100", "type": "socket"}},
        },
        "user": sock_user("989", "node_exporter"),
        "process": {"pid": 1408, "parent": {"pid": 1}, "name": "node_exporter", "executable": "/usr/local/bin/node_exporter",
                    "title": "/usr/local/bin/node_exporter --web.listen-address=:9100"},
        "tags": ["net"],
        "related": {"user": ["node_exporter"]},
    }, session=None))

    evs.append(auditd("web-01", "listen-for-connections", ["network"], ["start"], "success", "syscall", {
        "auditd": {
            "data": {"a0": "6", "a1": "1ff", "a2": "0", "a3": "0", "arch": "x86_64", "exit": "0",
                     "syscall": "listen", "tty": "(none)"},
            "summary": {"actor": {"primary": "unset", "secondary": "root"}, "how": "/usr/sbin/nginx",
                        "object": {"type": "socket"}},
        },
        "user": sock_user("0", "root"),
        "process": {"pid": 24395, "parent": {"pid": 1}, "name": "nginx", "executable": "/usr/sbin/nginx",
                    "title": "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"},
        "tags": ["net"],
        "related": {"user": ["root"]},
    }, session=None))

    # --- SSH login sequence (success): USER_AUTH, USER_ACCT, CRED_ACQ, USER_LOGIN, USER_START
    evs.append(auditd("web-01", "authenticated", ["authentication"], ["info"], "success", "user_auth", merge({
        "auditd": {
            "data": {"acct": "alice", "addr": "203.0.113.50", "hostname": "203.0.113.50", "op": "PAM:authentication",
                     "terminal": "ssh"},
            "summary": {"actor": {"primary": "unset", "secondary": "alice"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "ssh", "secondary": "203.0.113.50", "type": "user-session"}},
        },
        "user": {"effective": {"id": "1001", "name": "alice"}},
        "related": {"user": ["alice"]},
    }, json.loads(json.dumps(sshd_auth))), session=None))

    evs.append(auditd("web-01", "was-authorized", ["authentication"], ["info"], "success", "user_acct", merge({
        "auditd": {
            "data": {"acct": "alice", "addr": "203.0.113.50", "hostname": "203.0.113.50", "op": "PAM:accounting",
                     "terminal": "ssh"},
            "summary": {"actor": {"primary": "unset", "secondary": "alice"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "ssh", "secondary": "203.0.113.50", "type": "user-session"}},
        },
        "user": {"effective": {"id": "1001", "name": "alice"}},
        "related": {"user": ["alice"]},
    }, json.loads(json.dumps(sshd_auth))), session=None))

    evs.append(auditd("web-01", "acquired-credentials", ["authentication"], ["info"], "success", "cred_acq", merge({
        "auditd": {
            "data": {"acct": "alice", "addr": "203.0.113.50", "hostname": "203.0.113.50", "op": "PAM:setcred",
                     "terminal": "ssh"},
            "summary": {"actor": {"primary": "unset", "secondary": "alice"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "ssh", "secondary": "203.0.113.50", "type": "user-session"}},
        },
        "user": {"effective": {"id": "1001", "name": "alice"}},
        "related": {"user": ["alice"]},
    }, json.loads(json.dumps(sshd_auth))), session=None))

    evs.append(auditd("web-01", "logged-in", ["authentication"], ["start"], "success", "user_login", merge({
        "auditd": {
            "data": {"id": "1001", "hostname": "203.0.113.50", "op": "login", "terminal": "/dev/pts/0"},
            "summary": {"actor": {"primary": "alice", "secondary": "alice"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "/dev/pts/0", "secondary": "203.0.113.50", "type": "user-session"}},
        },
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"}},
        "source": {"ip": "203.0.113.50"},
        "network": {"direction": "ingress"},
        "related": {"user": ["alice"]},
    }, json.loads(json.dumps(sshd_auth))), session="12"))

    evs.append(auditd("web-01", "started-session", ["session"], ["start"], "success", "user_start", merge({
        "auditd": {
            "data": {"acct": "alice", "hostname": "203.0.113.50", "op": "PAM:session_open", "terminal": "ssh"},
            "summary": {"actor": {"primary": "alice", "secondary": "alice"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "ssh", "secondary": "203.0.113.50", "type": "user-session"}},
        },
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"}},
        "source": {"ip": "203.0.113.50"},
        "network": {"direction": "ingress"},
        "related": {"user": ["alice"]},
    }, json.loads(json.dumps(sshd_auth))), session="12"))

    # --- SSH brute force: wrong password (USER_AUTH fail) and invalid user (USER_LOGIN fail)
    evs.append(auditd("web-01", "authenticated", ["authentication"], ["info"], "failure", "user_auth", merge({
        "auditd": {
            "data": {"acct": "bob", "addr": "203.0.113.77", "hostname": "203.0.113.77", "op": "PAM:authentication",
                     "terminal": "ssh"},
            "summary": {"actor": {"primary": "unset", "secondary": "bob"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "ssh", "secondary": "203.0.113.77", "type": "user-session"}},
        },
        "user": {"effective": {"id": "1002", "name": "bob"}},
        "related": {"user": ["bob"]},
    }, {"process": {"executable": "/usr/sbin/sshd", "pid": 32001}}), session=None))

    evs.append(auditd("web-01", "logged-in", ["authentication"], ["start"], "failure", "user_login", {
        "auditd": {
            "data": {"acct": "admin", "op": "login", "terminal": "ssh"},
            "summary": {"actor": {"primary": "unset", "secondary": "admin"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "ssh", "secondary": "203.0.113.77", "type": "user-session"}},
        },
        "process": {"executable": "/usr/sbin/sshd", "pid": 32040},
        "user": {"effective": {"name": "admin"}},
        "source": {"ip": "203.0.113.77"},
        "network": {"direction": "ingress"},
        "related": {"user": ["admin"]},
    }, session=None))

    # --- sudo (privileged) success and su failure
    evs.append(auditd("web-01", "authenticated", ["authentication"], ["info"], "success", "user_auth", {
        "auditd": {
            "data": {"acct": "alice", "addr": "?", "hostname": "?", "op": "PAM:authentication", "terminal": "/dev/pts/0"},
            "summary": {"actor": {"primary": "alice", "secondary": "alice"}, "how": "/usr/bin/sudo",
                        "object": {"primary": "/dev/pts/0", "type": "user-session"}},
        },
        "process": {"executable": "/usr/bin/sudo", "pid": 24387},
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"}},
        "related": {"user": ["alice"]},
    }, session="12"))

    evs.append(auditd("web-01", "authenticated", ["authentication"], ["info"], "failure", "user_auth", {
        "auditd": {
            "data": {"acct": "root", "addr": "?", "hostname": "?", "op": "PAM:authentication", "terminal": "/dev/pts/1"},
            "summary": {"actor": {"primary": "bob", "secondary": "root"}, "how": "/usr/bin/su",
                        "object": {"primary": "/dev/pts/1", "type": "user-session"}},
        },
        "process": {"executable": "/usr/bin/su", "pid": 25190},
        "user": {"id": "1002", "name": "bob", "audit": {"id": "1002", "name": "bob"},
                 "effective": {"id": "0", "name": "root"}},
        "related": {"user": ["bob", "root"]},
    }, session="14"))

    evs.append(auditd("web-01", "ended-session", ["session"], ["end"], "success", "user_end", merge({
        "auditd": {
            "data": {"acct": "alice", "hostname": "203.0.113.50", "op": "PAM:session_close", "terminal": "ssh"},
            "summary": {"actor": {"primary": "alice", "secondary": "alice"}, "how": "/usr/sbin/sshd",
                        "object": {"primary": "ssh", "secondary": "203.0.113.50", "type": "user-session"}},
        },
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"}},
        "related": {"user": ["alice"]},
    }, json.loads(json.dumps(sshd_auth))), session="12"))

    # --- account management (run by alice through sudo: uid=0, auid=alice)
    def acct_mgmt(action, etype, mtype, how, op, obj_primary, extra, pid):
        body = {
            "auditd": {
                "data": {"addr": "?", "hostname": "web-01", "op": op, "terminal": "pts/0"},
                "summary": {"actor": {"primary": "alice", "secondary": "root"}, "how": how,
                            "object": {"primary": obj_primary, "type": "account"}},
            },
            "process": {"executable": how, "pid": pid},
            "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"},
                     "effective": {"id": "0", "name": "root"}},
        }
        merge(body, extra)
        return auditd("web-01", action, ["iam"], etype, "success", mtype, body, session="12")

    evs.append(acct_mgmt("added-group-account-to", ["group", "creation"], "add_group", "/usr/sbin/groupadd", "add-group",
                         "1010", {"auditd": {"data": {"id": "1010", "grp": "deploy"}},
                                  "group": {"id": "1010", "name": "deploy"},
                                  "related": {"user": ["alice", "root"]}}, 26001))
    evs.append(acct_mgmt("added-user-account", ["user", "creation"], "add_user", "/usr/sbin/useradd", "add-user",
                         "1010", {"auditd": {"data": {"id": "1010"}},
                                  "user": {"target": {"id": "1010", "name": "deploy"}},
                                  "related": {"user": ["alice", "deploy", "root"]}}, 26004))
    evs.append(auditd("web-01", "changed-password", ["iam"], ["user", "change"], "success", "user_chauthtok", {
        "auditd": {
            "data": {"acct": "deploy", "addr": "?", "hostname": "web-01", "op": "PAM:chauthtok", "terminal": "/dev/pts/0"},
            "summary": {"actor": {"primary": "alice", "secondary": "deploy"}, "how": "/usr/bin/passwd",
                        "object": {"primary": "/dev/pts/0", "type": "user-session"}},
        },
        "process": {"executable": "/usr/bin/passwd", "pid": 26010},
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"},
                 "effective": {"id": "0", "name": "root"}, "target": {"id": "1010", "name": "deploy"}},
        "related": {"user": ["alice", "deploy", "root"]},
    }, session="12"))
    evs.append(auditd("web-01", "modified-user-account", ["iam"], ["user", "change"], "success", "user_mgmt", {
        "auditd": {
            "data": {"acct": "deploy", "addr": "?", "hostname": "web-01", "op": "add-user-to-group", "grp": "sudo",
                     "terminal": "pts/0"},
            "summary": {"actor": {"primary": "alice", "secondary": "deploy"}, "how": "/usr/sbin/usermod",
                        "object": {"primary": "pts/0", "secondary": "web-01", "type": "user-session"}},
        },
        "process": {"executable": "/usr/sbin/usermod", "pid": 26015},
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"},
                 "effective": {"id": "0", "name": "root"}, "target": {"name": "deploy"}},
        "related": {"user": ["alice", "deploy", "root"]},
    }, session="12"))
    evs.append(auditd("web-01", "modified-group-account", ["iam"], ["group", "change"], "success", "grp_mgmt", {
        "auditd": {
            "data": {"acct": "deploy", "addr": "?", "hostname": "web-01", "op": "changing-group-name", "id": "1010",
                     "terminal": "pts/0"},
            "summary": {"actor": {"primary": "alice", "secondary": "deploy"}, "how": "/usr/sbin/groupmod",
                        "object": {"primary": "1010", "type": "account"}},
        },
        "process": {"executable": "/usr/sbin/groupmod", "pid": 26021},
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"},
                 "effective": {"id": "0", "name": "root"}},
        "group": {"name": "deploy"},
        "related": {"user": ["alice", "root"]},
    }, session="12"))
    evs.append(auditd("web-01", "locked-account", ["iam"], ["user", "info"], "success", "acct_lock", {
        "auditd": {
            "data": {"acct": "olduser", "addr": "?", "hostname": "web-01", "op": "locked-password", "id": "1004",
                     "terminal": "pts/0"},
            "summary": {"actor": {"primary": "alice", "secondary": "olduser"}, "how": "/usr/bin/passwd",
                        "object": {"primary": "pts/0", "type": "user-session"}},
        },
        "process": {"executable": "/usr/bin/passwd", "pid": 26030},
        "user": {"id": "1001", "name": "alice", "audit": {"id": "1001", "name": "alice"},
                 "effective": {"id": "0", "name": "root"}},
        "related": {"user": ["alice", "root"]},
    }, session="12"))
    evs.append(acct_mgmt("deleted-user-account", ["user", "deletion"], "del_user", "/usr/sbin/userdel", "delete-user",
                         "1004", {"auditd": {"data": {"id": "1004"}},
                                  "user": {"target": {"id": "1004", "name": "olduser"}},
                                  "related": {"user": ["alice", "olduser", "root"]}}, 26040))
    evs.append(acct_mgmt("deleted-group-account-from", ["group", "deletion"], "del_group", "/usr/sbin/userdel",
                         "delete-group", "1004", {"auditd": {"data": {"id": "1004", "grp": "olduser"}},
                                                  "group": {"id": "1004", "name": "olduser"},
                                                  "related": {"user": ["alice", "root"]}}, 26040))

    # --- services (systemd SERVICE_START / SERVICE_STOP)
    def service(action, etype, mtype, unit, outcome, host="web-01"):
        return auditd(host, action, ["process"], etype, outcome, mtype, {
            "auditd": {
                "data": {"unit": unit, "comm": "systemd", "terminal": "?", "addr": "?", "hostname": "?"},
                "summary": {"actor": {"primary": "unset", "secondary": "root"}, "how": "/usr/lib/systemd/systemd",
                            "object": {"primary": unit, "type": "service"}},
            },
            "process": {"pid": 1, "name": "systemd", "executable": "/usr/lib/systemd/systemd"},
            "user": {"id": "0", "name": "root"},
            "related": {"user": ["root"]},
        }, session=None)

    evs.append(service("stopped-service", ["end"], "service_stop", "nginx", "success"))
    evs.append(service("started-service", ["start"], "service_start", "nginx", "success"))
    evs.append(service("started-service", ["start"], "service_start", "myapp", "failure", host="db-01"))

    # --- audit configuration change (auditctl -D) and file watches (-w /etc/shadow -p rwa -k identity)
    evs.append(auditd("web-01", "changed-audit-configuration", ["process", "configuration"], ["change"], "success",
                      "config_change", {
                          "auditd": {
                              "data": {"op": "remove_rule", "key": "identity", "list": "4", "res": "1"},
                              "summary": {"actor": {"primary": "alice", "secondary": "root"}, "how": "/usr/sbin/auditctl",
                                          "object": {"primary": "remove_rule", "type": "audit-config"}},
                          },
                          "process": {"pid": 26100, "name": "auditctl", "executable": "/usr/sbin/auditctl"},
                          "user": {"audit": {"id": "1001", "name": "alice"}},
                          "related": {"user": ["alice"]},
                      }, session="12"))

    def file_sys(action, etype, syscall, a, path, mode, owner, how, pname, pid, title, tags, outcome="success"):
        return auditd("web-01", action, ["file"], etype, outcome, "syscall", {
            "auditd": {
                "data": dict({"arch": "x86_64", "exit": "3" if syscall.startswith("open") else "0",
                              "syscall": syscall, "tty": "pts0"}, **a),
                "paths": [{"dev": "fd:00", "inode": "1310745", "item": "0", "mode": "0100" + mode[1:], "name": path,
                           "nametype": "NORMAL", "ogid": "0", "ouid": "0", "rdev": "00:00"}],
                "summary": {"actor": {"primary": "alice", "secondary": "root"}, "how": how,
                            "object": {"primary": path, "type": "file"}},
            },
            "user": syscall_user("0", "root", "1001", "alice"),
            "process": {"pid": pid, "parent": {"pid": 24391}, "name": pname, "executable": how,
                        "working_directory": "/root", "title": title},
            "file": {"path": path, "device": "00:00", "inode": "1310745", "mode": mode, "uid": "0", "gid": owner[1],
                     "owner": "root", "group": owner[0]},
            "tags": tags,
            "related": {"user": ["alice", "root"]},
        }, session="12")

    # openat(dirfd, path, flags=O_WRONLY|O_CREAT|O_TRUNC 0x241, mode)
    evs.append(file_sys("opened-file", ["info"], "openat",
                        {"a0": "ffffff9c", "a1": "7ffc6a1b2c30", "a2": "241", "a3": "1b6"},
                        "/etc/shadow", "0640", ("shadow", "42"), "/usr/bin/vim.basic", "vim", 26150,
                        "vim /etc/shadow", ["identity"]))
    # openat(dirfd, path, flags=O_RDONLY|O_CLOEXEC 0x80000)
    evs.append(file_sys("opened-file", ["info"], "openat",
                        {"a0": "ffffff9c", "a1": "7ffe2c3d4e50", "a2": "80000", "a3": "0"},
                        "/etc/shadow", "0640", ("shadow", "42"), "/usr/bin/cat", "cat", 26160,
                        "cat /etc/shadow", ["identity"]))
    evs.append(file_sys("changed-file-permissions-of", ["change"], "fchmodat",
                        {"a0": "ffffff9c", "a1": "55f0a1b2c3d0", "a2": "1a0", "a3": "0"},
                        "/etc/sudoers.d/90-deploy", "0640", ("root", "0"), "/usr/bin/chmod", "chmod", 26170,
                        "chmod 0640 /etc/sudoers.d/90-deploy", ["sudoers"]))
    evs.append(file_sys("deleted", ["deletion"], "unlinkat",
                        {"a0": "ffffff9c", "a1": "5603e2f1a0b0", "a2": "0", "a3": "0"},
                        "/var/log/auth.log.1", "0640", ("adm", "4"), "/usr/bin/rm", "rm", 26180,
                        "rm -f /var/log/auth.log.1", ["log_tamper"]))
    evs.append(file_sys("renamed", ["change"], "renameat2",
                        {"a0": "ffffff9c", "a1": "7ffd1c2b3a40", "a2": "ffffff9c", "a3": "7ffd1c2b3a80"},
                        "/etc/passwd", "0644", ("root", "0"), "/usr/sbin/useradd", "useradd", 26004,
                        "useradd -m -s /bin/bash deploy", ["identity"]))

    evs.append(auditd("db-01", "booted-system", ["host"], ["start"], "success", "system_boot", {
        "auditd": {
            "data": {"comm": "systemd-update-utmp", "terminal": "?", "addr": "?", "hostname": "?"},
            "summary": {"actor": {"primary": "unset", "secondary": "root"},
                        "how": "/usr/lib/systemd/systemd-update-utmp", "object": {"type": "system"}},
        },
        "process": {"pid": 842, "executable": "/usr/lib/systemd/systemd-update-utmp"},
        "user": {"id": "0", "name": "root"},
        "related": {"user": ["root"]},
    }, session=None))
    return evs


# --------------------------------------------------------------------------- file_integrity

def fim(host, actions, etypes, file_fields, hashes=None, process=None):
    ev = envelope(host, "file_integrity", "file")
    ev["event"].update({"kind": "event", "category": ["file"], "type": etypes, "action": actions})
    f = dict(file_fields)
    if hashes:
        f["hash"] = hashes
    ev["file"] = f
    if process:
        ev["process"] = process
    return ev


def file_meta(path, inode, size, mode, owner, group, uid, gid, mtime, ctime, mime=None, extra=None):
    name = path.rsplit("/", 1)[-1]
    meta = {"path": path, "inode": inode, "mtime": mtime, "ctime": ctime, "name": name,
            "extension": name.rsplit(".", 1)[-1] if "." in name else "", "size": size, "type": "file",
            "uid": uid, "gid": gid, "mode": mode, "owner": owner, "group": group}
    if mime:
        meta["mime_type"] = mime
    if extra:
        meta.update(extra)
    return meta


def gen_fim():
    evs = []
    evs.append(fim("web-01", ["created"], ["creation"],
                   file_meta("/etc/cron.d/backup", "1311020", 112, "0644", "root", "root", "0", "0",
                             "2026-10-24T08:21:04.119382551Z", "2026-10-24T08:21:04.119382551Z", "text/plain"),
                   {"sha1": "3f786850e387550fdab836ed7e6dc881de23001b",
                    "sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"}))
    evs.append(fim("web-01", ["created", "updated"], ["change", "creation"],
                   file_meta("/usr/local/bin/helper", "1311055", 18432, "0755", "root", "root", "0", "0",
                             "2026-10-24T08:22:40.007113002Z", "2026-10-24T08:22:40.007113002Z",
                             "application/x-executable"),
                   {"sha1": "a54d88e06612d820bc3be72877c74f257b561b19",
                    "sha256": "b9e2c1a8a6f0f0d71f6a3b0e8c4f4c2d6e3d9f1c7b2a6e5d4c3b2a1f0e9d8c7b"}))
    evs.append(fim("web-01", ["updated"], ["change"],
                   file_meta("/etc/ssh/sshd_config", "1310922", 3297, "0644", "root", "root", "0", "0",
                             "2026-10-24T08:23:15.551920114Z", "2026-10-24T08:23:15.551920114Z", "text/plain"),
                   {"sha1": "0f5a1bcd2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}))
    evs.append(fim("web-01", ["attributes_modified"], ["change"],
                   file_meta("/etc/sudoers", "1310801", 1800, "0640", "root", "root", "0", "0",
                             "2026-09-30T10:02:11.000000000Z", "2026-10-24T08:24:01.402981557Z", "text/plain"),
                   {"sha1": "8ab686eafeb1f44702738c8b0f24f2567c36da6d",
                    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}))
    # deletions carry no file metadata or hashes (e.Info == nil)
    evs.append(fim("web-01", ["deleted"], ["deletion"], {"path": "/etc/cron.d/old-job"}))
    evs.append(fim("web-01", ["moved"], ["change"],
                   file_meta("/etc/nginx/sites-enabled/default.disabled", "1312004", 2412, "0644", "root", "root", "0",
                             "0", "2026-08-01T12:00:00.000000000Z", "2026-10-24T08:25:12.880120113Z", "text/plain"),
                   {"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"}))
    evs.append(fim("db-01", ["initial_scan"], ["info"],
                   file_meta("/etc/hosts", "524301", 221, "0644", "root", "root", "0", "0",
                             "2026-05-02T09:14:55.000000000Z", "2026-05-02T09:14:55.000000000Z", "text/plain"),
                   {"sha1": "7b52009b64fd0a2a49e6d8a939753077792b0554",
                    "sha256": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"}))
    # ebpf/kprobes backends add the process (and its user) that made the change
    evs.append(fim("db-01", ["updated"], ["change"],
                   file_meta("/etc/passwd", "524290", 2087, "0644", "root", "root", "0", "0",
                             "2026-10-24T08:26:30.311200981Z", "2026-10-24T08:26:30.311200981Z", "text/plain"),
                   {"sha1": "1b6453892473a467d07372d45eb05abc2031647a",
                    "sha256": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"},
                   {"pid": 91002, "name": "useradd", "entity_id": "Rm9vYmFyMTIzNDU2Nzg5MA",
                    "user": {"id": "0", "name": "root"}, "group": {"id": "0", "name": "root"}}))
    evs.append(fim("web-01", ["created"], ["creation"],
                   file_meta("/tmp/.cache/su", "2621501", 67816, "04755", "root", "root", "0", "0",
                             "2026-10-24T08:27:45.120044871Z", "2026-10-24T08:27:45.120044871Z",
                             "application/x-executable", {"setuid": True}),
                   {"sha1": "ac3478d69a3c81fa62e60f5c3696165a4e5e6ac4",
                    "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"}))
    return evs


# --------------------------------------------------------------------------- system/*

def system(host, dataset, kind, category, etype, action, body):
    ev = envelope(host, "system", dataset)
    ev["event"].update({"kind": kind, "action": action})
    if category is not None:
        ev["event"]["category"] = category
    if etype is not None:
        ev["event"]["type"] = etype
    return merge(ev, body)


def proc_user(uid, name, group):
    return {"id": uid, "name": name, "group": {"id": uid, "name": group},
            "effective": {"id": uid, "group": {"id": uid}}, "saved": {"id": uid, "group": {"id": uid}}}


def gen_process():
    evs = []
    evs.append(system("web-01", "process", "state", ["process"], ["info"], "existing_process", {
        "message": "Process sshd (PID: 1102) by user root is RUNNING",
        "process": {"name": "sshd", "args": ["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"], "pid": 1102,
                    "parent": {"pid": 1}, "working_directory": "/", "executable": "/usr/sbin/sshd",
                    "start": "2026-10-20T06:11:02.220Z", "entity_id": "kQ1m2b3n4v5c6x7z",
                    "hash": {"sha1": "6f1ed002ab5595859014ebf0951522d9f6a1c2d3"}},
        "user": proc_user("0", "root", "root"),
    }))
    evs.append(system("web-01", "process", "event", ["process"], ["start"], "process_started", {
        "message": "Process bash (PID: 24391) by user alice STARTED",
        "process": {"name": "bash", "args": ["bash", "-c", "curl -fsSL https://downloads.example.com/agent.sh | sh"],
                    "pid": 24391, "parent": {"pid": 24388}, "working_directory": "/root",
                    "executable": "/usr/bin/bash", "start": "2026-10-24T08:01:12.410Z",
                    "entity_id": "Zp9o8i7u6y5t4r3e",
                    "hash": {"sha1": "1c9e4a1b2f0d3e5c7a9b8d6f4e2c0a1b3d5f7e9c",
                             "sha256": "59b4e1b2c3d4a5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e"}},
        "user": proc_user("1001", "alice", "alice"),
    }))
    evs.append(system("web-01", "process", "event", ["process"], ["end"], "process_stopped", {
        "message": "Process bash (PID: 24391) by user alice STOPPED",
        "process": {"name": "bash", "args": ["bash", "-c", "curl -fsSL https://downloads.example.com/agent.sh | sh"],
                    "pid": 24391, "parent": {"pid": 24388}, "working_directory": "/root",
                    "executable": "/usr/bin/bash", "start": "2026-10-24T08:01:12.410Z",
                    "entity_id": "Zp9o8i7u6y5t4r3e",
                    "hash": {"sha1": "1c9e4a1b2f0d3e5c7a9b8d6f4e2c0a1b3d5f7e9c",
                             "sha256": "59b4e1b2c3d4a5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e"}},
        "user": proc_user("1001", "alice", "alice"),
    }))
    # quark (eBPF) backend: process.backend: kernel_tracing
    evs.append(system("db-01", "process", "event", ["process"], ["start", "change", "end"], "process_ran", {
        "message": "Process id (PID: 91010) by user carol RAN",
        "process": {"name": "id", "args": ["id", "-Gn"], "args_count": 2, "pid": 91010, "parent": {"pid": 90180},
                    "working_directory": "/home/carol", "executable": "/usr/bin/id", "exit_code": 0,
                    "start": "2026-10-24T08:30:01.004Z", "entity_id": "Yt5r4e3w2q1a0s9d", "interactive": True,
                    "tty": {"char_device": {"major": 136, "minor": 0}},
                    "hash": {"sha256": "8e2c1f0a9b7d6e5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c"}},
        "user": {"id": "1005", "name": "carol", "group": {"id": "1005", "name": "carol"},
                 "effective": {"id": "1005", "group": {"id": "1005"}}, "saved": {"id": "1005", "group": {"id": "1005"}}},
    }))
    evs.append(system("db-01", "process", "event", ["process"], ["change"], "process_changed_image", {
        "message": "Process python3 (PID: 90180) by user carol CHANGED IMAGE",
        "process": {"name": "python3", "args": ["python3", "/home/carol/report.py"], "args_count": 2, "pid": 90180,
                    "parent": {"pid": 90177}, "working_directory": "/home/carol",
                    "executable": "/usr/bin/python3.9", "start": "2026-10-24T08:29:58.771Z",
                    "entity_id": "Ui8y7t6r5e4w3q2a", "interactive": True,
                    "hash": {"sha256": "1f2e3d4c5b6a79880f1e2d3c4b5a69788f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c"}},
        "user": {"id": "1005", "name": "carol", "group": {"id": "1005", "name": "carol"},
                 "effective": {"id": "1005", "group": {"id": "1005"}}, "saved": {"id": "1005", "group": {"id": "1005"}}},
    }))
    return evs


def gen_socket():
    evs = []

    def flow(host, direction, transport, src, dst, proc, user, start, end, community, inet="ipv4"):
        dur = int((datetime.fromisoformat(end.replace("Z", "+00:00")) -
                   datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds() * 1e9)
        body = {
            "source": dict(src), "client": dict(src), "destination": dict(dst), "server": dict(dst),
            "network": {"direction": direction, "type": inet, "transport": transport,
                        "packets": src["packets"] + dst["packets"], "bytes": src["bytes"] + dst["bytes"],
                        "community_id": community},
            "flow": {"final": True, "complete": True},
            "related": {"ip": [src["ip"], dst["ip"]]},
            "system": {"audit": {"socket": {"kernel_sock_address": "0xffff8d2e1c4a7000", "uid": int(user[0]),
                                            "gid": int(user[0]), "euid": int(user[0]), "egid": int(user[0])}}},
        }
        if proc:
            body["process"] = proc
            body["user"] = {"id": user[0], "name": user[1]}
            body["group"] = {"id": user[0], "name": user[1]}
            body["related"]["user"] = [user[1]]
        ev = system(host, "socket", "event", ["network"], ["info", "connection"], "network_flow", body)
        ev["event"].update({"start": start, "end": end, "duration": dur})
        return ev

    evs.append(flow("web-01", "egress", "tcp",
                    {"ip": "10.20.1.15", "port": 40192, "packets": 14, "bytes": 1893},
                    {"ip": "198.51.100.20", "port": 443, "packets": 18, "bytes": 22541,
                     "domain": "downloads.example.com"},
                    {"pid": 24410, "name": "curl", "args": ["curl", "-fsSL", "https://downloads.example.com/agent.sh"],
                     "executable": "/usr/bin/curl", "created": "2026-10-24T08:01:13.002Z",
                     "entity_id": "Lk3j2h1g0f9d8s7a"},
                    ("0", "root"), "2026-10-24T08:01:13.010Z", "2026-10-24T08:01:14.512Z",
                    "1:mQ7y0kq7Vf3Kq6v8pN5H4o1nR2s="))
    evs.append(flow("web-01", "ingress", "tcp",
                    {"ip": "203.0.113.50", "port": 51522, "packets": 211, "bytes": 31877},
                    {"ip": "10.20.1.15", "port": 22, "packets": 198, "bytes": 52110},
                    {"pid": 31877, "name": "sshd", "args": ["sshd: alice [priv]"], "executable": "/usr/sbin/sshd",
                     "created": "2026-10-24T08:00:41.300Z", "entity_id": "Qa1s2d3f4g5h6j7k"},
                    ("0", "root"), "2026-10-24T08:00:41.288Z", "2026-10-24T08:19:02.004Z",
                    "1:LQU9qZlK+B5F3KDmev6m5PMibrg="))
    evs.append(flow("web-01", "egress", "udp",
                    {"ip": "10.20.1.15", "port": 58211, "packets": 1, "bytes": 74},
                    {"ip": "10.20.0.2", "port": 53, "packets": 1, "bytes": 129},
                    {"pid": 612, "name": "systemd-resolve", "args": ["/usr/lib/systemd/systemd-resolved"],
                     "executable": "/usr/lib/systemd/systemd-resolved", "created": "2026-10-20T06:10:55.010Z",
                     "entity_id": "Zx9c8v7b6n5m4l3k"},
                    ("991", "systemd-resolve"), "2026-10-24T08:01:12.990Z", "2026-10-24T08:01:13.004Z",
                    "1:3mHq2b0rD0mWJk2nI5mPq8yT9cA="))
    evs.append(flow("db-01", "egress", "tcp",
                    {"ip": "2001:db8:10::21", "port": 49812, "packets": 9, "bytes": 1120},
                    {"ip": "2001:db8:ff::443", "port": 443, "packets": 11, "bytes": 8890},
                    {"pid": 1408, "name": "node_exporter", "args": ["/usr/local/bin/node_exporter"],
                     "executable": "/usr/local/bin/node_exporter", "created": "2026-10-20T06:11:30.000Z",
                     "entity_id": "Ws2e3r4t5y6u7i8o"},
                    ("989", "node_exporter"), "2026-10-24T08:31:00.120Z", "2026-10-24T08:31:00.871Z",
                    "1:9vJ3eRk1Xq0pT7uYw2zA5cB8dE4=", inet="ipv6"))
    evs.append(flow("db-01", "unknown", "udp",
                    {"ip": "10.20.2.21", "port": 41000, "packets": 2, "bytes": 180},
                    {"ip": "10.20.0.3", "port": 123, "packets": 2, "bytes": 180},
                    None, ("0", "root"), "2026-10-24T08:32:10.000Z", "2026-10-24T08:32:10.050Z",
                    "1:p0O9i8U7y6T5r4E3w2Q1aZsXdCf="))
    return evs


def gen_login():
    evs = []
    evs.append(system("web-01", "login", "event", ["authentication"], ["start", "authentication_success"],
                      "user_login", {
                          "event": {"origin": "/var/log/wtmp", "outcome": "success"},
                          "message": "Login by user alice (UID: 1001) on pts/0 (PID: 31890) from 203.0.113.50 "
                                     "(IP: 203.0.113.50)",
                          "user": {"name": "alice", "id": 1001, "terminal": "pts/0"},
                          "process": {"pid": 31890},
                          "source": {"ip": "203.0.113.50"},
                          "related": {"user": ["alice"], "ip": ["203.0.113.50"]},
                      }))
    evs.append(system("web-01", "login", "event", ["authentication"], ["start", "authentication_failure"],
                      "user_login", {
                          "event": {"origin": "/var/log/btmp", "outcome": "failure"},
                          "message": "Failed login by user admin (UID: -1) on ssh:notty (PID: 32040) from "
                                     "203.0.113.77 (IP: 203.0.113.77)",
                          "user": {"name": "admin", "terminal": "ssh:notty"},
                          "process": {"pid": 32040},
                          "source": {"ip": "203.0.113.77"},
                          "related": {"user": ["admin"], "ip": ["203.0.113.77"]},
                      }))
    evs.append(system("web-01", "login", "event", ["authentication"], ["end"], "user_logout", {
        "event": {"origin": "/var/log/wtmp"},
        "message": "Logout by user alice (UID: 1001) on pts/0 (PID: 31890) from 203.0.113.50 (IP: 203.0.113.50)",
        "user": {"name": "alice", "id": 1001, "terminal": "pts/0"},
        "process": {"pid": 31890},
        "source": {"ip": "203.0.113.50"},
        "related": {"user": ["alice"], "ip": ["203.0.113.50"]},
    }))
    evs.append(system("db-01", "login", "event", ["host"], ["end"], "shutdown", {
        "event": {"origin": "/var/log/wtmp"},
        "message": "System shutdown",
        "user": {"terminal": "~~"},
    }))
    evs.append(system("db-01", "login", "event", ["host"], ["start"], "boot", {
        "event": {"origin": "/var/log/wtmp"},
        "message": "System boot",
        "user": {"terminal": "~~"},
    }))
    return evs


def gen_user():
    evs = []

    def u(host, kind, etype, action, name, uid, gid, home, shell, ptype, groups, msg, info=None, changed=None):
        audit_user = {"name": name, "uid": uid, "gid": gid, "dir": home, "shell": shell,
                      "password": {"type": ptype},
                      "group": [{"name": g, "gid": i, "id": i} for g, i in groups]}
        if info:
            audit_user["user_information"] = info
        if changed:
            audit_user["password"]["last_changed"] = changed
        return system(host, "user", kind, ["iam"], [etype], action, {
            "message": msg,
            "user": {"id": uid, "name": name, "entity_id": "U" + uid.zfill(8) + host.replace("-", ""),
                     "group": {"id": groups[0][1], "name": groups[0][0]}},
            "related": {"user": [name]},
            "system": {"audit": {"user": audit_user}},
        })

    evs.append(u("web-01", "state", "info", "existing_user", "root", "0", "0", "/root", "/bin/bash", "shadow_password",
                 [("root", "0")], "Existing user root (UID: 0, Groups: root)", "root",
                 "2026-03-11T00:00:00Z"))
    evs.append(u("web-01", "state", "info", "existing_user", "alice", "1001", "1001", "/home/alice", "/bin/bash",
                 "shadow_password", [("alice", "1001"), ("sudo", "27")],
                 "Existing user alice (UID: 1001, Groups: alice,sudo)", "Alice Admin,,,", "2026-08-02T00:00:00Z"))
    evs.append(u("web-01", "state", "info", "existing_user", "www-data", "33", "33", "/var/www", "/usr/sbin/nologin",
                 "password_disabled", [("www-data", "33")], "Existing user www-data (UID: 33, Groups: www-data)",
                 "www-data"))
    evs.append(u("web-01", "event", "creation", "user_added", "deploy", "1010", "1010", "/home/deploy", "/bin/bash",
                 "shadow_password", [("deploy", "1010")], "New user deploy (UID: 1010, Groups: deploy)"))
    evs.append(u("web-01", "event", "change", "user_changed", "deploy", "1010", "1010", "/home/deploy", "/bin/bash",
                 "shadow_password", [("deploy", "1010"), ("sudo", "27")],
                 "Changed user deploy (UID: 1010, Groups: deploy,sudo)"))
    evs.append(u("web-01", "event", "change", "password_changed", "deploy", "1010", "1010", "/home/deploy",
                 "/bin/bash", "shadow_password", [("deploy", "1010"), ("sudo", "27")],
                 "Password of user deploy (UID: 1010) changed", changed="2026-10-24T00:00:00Z"))
    evs.append(u("web-01", "event", "deletion", "user_removed", "olduser", "1004", "1004", "/home/olduser",
                 "/bin/bash", "shadow_password", [("olduser", "1004")], "User olduser (UID: 1004) removed"))
    return evs


def gen_package():
    evs = []

    def p(host, kind, etype, action, name, version, ptype, summary, msg, arch="amd64", release=None, size=None):
        ecs = {"name": name, "version": version, "type": ptype, "description": summary,
               "installed": "2026-10-24T08:40:00Z",
               # Auditbeat bug (package.go): package.architecture is populated from the license value.
               "architecture": "GPL-2.0"}
        audit_pkg = {"name": name, "version": version, "arch": arch, "summary": summary,
                     "installtime": "2026-10-24T08:40:00Z", "license": "GPL-2.0",
                     "entity_id": "P" + name.replace("-", "")[:10] + host.replace("-", "")}
        if release:
            audit_pkg["release"] = release
        if size:
            audit_pkg["size"] = size
            ecs["size"] = size
        ecs["license"] = "GPL-2.0"
        return system(host, "package", kind, ["package"], [etype], action, {
            "message": msg, "package": ecs, "system": {"audit": {"package": audit_pkg}}})

    evs.append(p("web-01", "state", "info", "existing_package", "openssl", "3.0.13-0ubuntu3.3", "dpkg",
                 "Secure Sockets Layer toolkit - cryptographic utility",
                 "Package openssl (3.0.13-0ubuntu3.3) is already installed", size=2128))
    evs.append(p("web-01", "event", "installation", "package_installed", "nmap", "7.94+git20230807.3be01efb1+dfsg-3build2",
                 "dpkg", "The Network Mapper", "Package nmap (7.94+git20230807.3be01efb1+dfsg-3build2) installed",
                 size=4476))
    evs.append(p("web-01", "event", "change", "package_updated", "openssl", "3.0.13-0ubuntu3.4", "dpkg",
                 "Secure Sockets Layer toolkit - cryptographic utility",
                 "Package openssl (3.0.13-0ubuntu3.4) updated", size=2128))
    evs.append(p("db-01", "event", "deletion", "package_removed", "telnet", "0.17", "rpm",
                 "The client program for the Telnet remote login protocol",
                 "Package telnet (0.17-85.el9) removed", arch="x86_64", release="85.el9", size=123))
    return evs


def gen_host():
    evs = []
    for host, kind, etype, action, msg in (
        ("web-01", "state", "info", "host", "Ubuntu host web-01 (IP: 10.20.1.15) is up for 4 days, 2 hours, 1 minute"),
        ("db-01", "event", "start", "reboot", "Red Hat Enterprise Linux host db-01 (IP: 10.20.2.21) restarted"),
        ("web-01", "event", "change", "hostname_changed", "Hostname changed from web-01-old to web-01"),
    ):
        h = HOSTS[host]
        audit_host = {
            "uptime": 352860000000000, "boottime": "2026-10-20T06:10:00Z", "timezone.name": "UTC",
            "timezone.offset.sec": 0, "hostname": h["hostname"], "id": h["id"], "architecture": h["architecture"],
            "os": {k: v for k, v in h["os"].items() if k != "type"}, "containerized": False,
            "ip": h["ip"], "mac": h["mac"],
        }
        audit_host["os"]["type"] = h["os"]["type"]
        evs.append(system(host, "host", kind, ["host"], [etype], action, {
            "message": msg, "system": {"audit": {"host": audit_host}}}))
    return evs


def write(name, events):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, separators=(",", ":"), sort_keys=False) + "\n")
    print("%-34s %3d events" % (name, len(events)))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    write("auditbeat_auditd.ndjson", gen_auditd())
    write("auditbeat_file_integrity.ndjson", gen_fim())
    write("auditbeat_system_process.ndjson", gen_process())
    write("auditbeat_system_socket.ndjson", gen_socket())
    write("auditbeat_system_login.ndjson", gen_login())
    write("auditbeat_system_user.ndjson", gen_user())
    write("auditbeat_system_package.ndjson", gen_package())
    write("auditbeat_system_host.ndjson", gen_host())


if __name__ == "__main__":
    main()
