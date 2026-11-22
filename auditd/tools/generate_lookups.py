#!/usr/bin/env python3
"""Generate the SOC-TA-auditd lookup tables.

auditd_actions.csv
    Built from the ACTIONS table below: the CIM action / status /
    change_type / object_category / result / signature of every audit event
    class. The key is auditd_action (record type, or syscall name for kernel
    syscall events; see EVAL-auditd_action in props.conf). Rows marked OUTCOME
    are expanded into a "success" row and a "*" (any other outcome) row;
    specific rows come first because the lookup uses WILDCARD(auditd_outcome)
    with max_matches = 1.

auditd_record_types.csv
    Record type name -> numeric ID and description. Derived from the record
    type table of the Auditbeat add-on in this repository
    (auditbeat/SOC-TA-auditbeat/lookups/auditd_message_types.csv: go-libaudit
    v2.6.2 plus the Linux and audit-userspace headers), with upper-case names
    as they appear in audit.log.

Usage: python3 auditd/tools/generate_lookups.py
"""

import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LOOKUP_DIR = os.path.normpath(os.path.join(HERE, "..", "SOC-TA-auditd", "lookups"))
AUDITBEAT_TYPES = os.path.normpath(os.path.join(HERE, "..", "..", "auditbeat", "SOC-TA-auditbeat", "lookups", "auditd_message_types.csv"))

OUTCOME = "OUTCOME"  # expand into success / failure rows
ANY = "*"

# (auditd_action, outcome, action, change_type, object_category, result, signature)
# OUTCOME rows: action and signature may be "success value|failure value".
ACTIONS = [
    # --- Endpoint.Processes
    ("execve", OUTCOME, "allowed|blocked", "", "", "", "Process executed|Process execution failed"),
    ("execveat", OUTCOME, "allowed|blocked", "", "", "", "Process executed|Process execution failed"),
    ("USER_CMD", OUTCOME, "allowed|blocked", "", "", "", "Command run via sudo|Command via sudo failed"),
    # --- Network_Traffic / Endpoint.Ports
    ("connect", OUTCOME, "allowed|blocked", "", "", "", "Outbound network connection|Outbound network connection failed"),
    ("accept", OUTCOME, "allowed|blocked", "", "", "", "Inbound network connection accepted|Inbound network connection failed"),
    ("accept4", OUTCOME, "allowed|blocked", "", "", "", "Inbound network connection accepted|Inbound network connection failed"),
    ("bind", OUTCOME, "", "", "", "", "Socket bound to local address|Socket bind failed"),
    ("listen", OUTCOME, "", "", "", "", "Socket listening for connections|Socket listen failed"),
    # --- Endpoint.Services
    ("SERVICE_START", OUTCOME, "started|started", "", "service", "", "Service started|Service failed to start"),
    ("SERVICE_STOP", OUTCOME, "stopped|stopped", "", "service", "", "Service stopped|Service stopped with failure"),
    # --- Authentication and sessions
    ("USER_AUTH", OUTCOME, "success|failure", "", "", "", "PAM authentication succeeded|PAM authentication failed"),
    ("USER_LOGIN", OUTCOME, "success|failure", "", "", "", "User logged in|User login failed"),
    ("USER_LOGOUT", OUTCOME, "logoff|logoff", "", "", "", "User logged out|User logout failed"),
    ("USER_ACCT", OUTCOME, "success|failure", "", "", "", "PAM account authorization succeeded|PAM account authorization failed"),
    ("USER_ERR", OUTCOME, "failure|failure", "", "", "", "User authentication error|User authentication error"),
    ("CRED_ACQ", OUTCOME, "", "", "", "", "PAM credentials acquired|PAM credentials acquisition failed"),
    ("CRED_REFR", OUTCOME, "", "", "", "", "PAM credentials refreshed|PAM credentials refresh failed"),
    ("CRED_DISP", OUTCOME, "", "", "", "", "PAM credentials disposed|PAM credentials disposal failed"),
    ("USER_START", OUTCOME, "", "", "", "", "Session opened|Session open failed"),
    ("USER_END", OUTCOME, "", "", "", "", "Session closed|Session close failed"),
    ("LOGIN", OUTCOME, "", "", "", "", "Login UID assigned|Login UID assignment failed"),
    # --- Change.Account_Management
    ("ADD_USER", OUTCOME, "created|created", "AAA", "user", "", "User account created|User account creation failed"),
    ("DEL_USER", OUTCOME, "deleted|deleted", "AAA", "user", "", "User account deleted|User account deletion failed"),
    ("USER_MGMT", OUTCOME, "modified|modified", "AAA", "user", "", "User account modified|User account modification failed"),
    ("USER_CHAUTHTOK", OUTCOME, "modified|modified", "AAA", "user", "", "User password changed|User password change failed"),
    ("ACCT_LOCK", OUTCOME, "lockout|lockout", "AAA", "user", "lockout", "User account locked|User account lock failed"),
    ("ACCT_UNLOCK", OUTCOME, "unlocked|unlocked", "AAA", "user", "", "User account unlocked|User account unlock failed"),
    ("ANOM_LOGIN_FAILURES", ANY, "lockout", "AAA", "user", "lockout", "Account locked after too many failed logins"),
    ("ROLE_ASSIGN", OUTCOME, "modified|modified", "AAA", "user", "", "Role assigned to user|Role assignment failed"),
    ("ROLE_REMOVE", OUTCOME, "modified|modified", "AAA", "user", "", "Role removed from user|Role removal failed"),
    ("ADD_GROUP", OUTCOME, "created|created", "AAA", "group", "", "Group created|Group creation failed"),
    ("DEL_GROUP", OUTCOME, "deleted|deleted", "AAA", "group", "", "Group deleted|Group deletion failed"),
    ("GRP_MGMT", OUTCOME, "modified|modified", "AAA", "group", "", "Group modified|Group modification failed"),
    ("GRP_CHAUTHTOK", OUTCOME, "modified|modified", "AAA", "group", "", "Group password changed|Group password change failed"),
    # --- Change.Auditing_Changes
    ("CONFIG_CHANGE", OUTCOME, "modified|modified", "audit", "audit_rule", "",
     "Audit configuration changed|Audit configuration change failed"),
    ("DAEMON_START", OUTCOME, "started|started", "audit", "service", "", "Audit daemon started|Audit daemon start failed"),
    ("DAEMON_END", OUTCOME, "stopped|stopped", "audit", "service", "", "Audit daemon stopped|Audit daemon stop failed"),
    ("DAEMON_ABORT", ANY, "stopped", "audit", "service", "", "Audit daemon aborted"),
    # --- Change.Endpoint_Changes
    ("SOFTWARE_UPDATE:install", OUTCOME, "created|created", "software", "package", "", "Package installed|Package install failed"),
    ("SOFTWARE_UPDATE:update", OUTCOME, "updated|updated", "software", "package", "", "Package updated|Package update failed"),
    ("SOFTWARE_UPDATE:remove", OUTCOME, "deleted|deleted", "software", "package", "", "Package removed|Package removal failed"),
    ("SYSTEM_BOOT", OUTCOME, "modified|modified", "restart", "host", "", "System booted|System boot failed"),
    ("SYSTEM_SHUTDOWN", OUTCOME, "stopped|stopped", "shutdown", "host", "", "System shutdown|System shutdown failed"),
    # --- Endpoint.Filesystem (watches)
    ("open:read", OUTCOME, "read|read", "filesystem", "file", "", "File opened for reading|File open for reading failed"),
    ("open:modified", OUTCOME, "modified|modified", "filesystem", "file", "", "File opened for writing|File open for writing failed"),
    ("open:created", OUTCOME, "created|created", "filesystem", "file", "", "File created|File creation failed"),
    ("truncate", OUTCOME, "modified|modified", "filesystem", "file", "", "File truncated|File truncation failed"),
    ("ftruncate", OUTCOME, "modified|modified", "filesystem", "file", "", "File truncated|File truncation failed"),
    ("fallocate", OUTCOME, "modified|modified", "filesystem", "file", "", "File space allocated|File space allocation failed"),
    ("unlink", OUTCOME, "deleted|deleted", "filesystem", "file", "", "File deleted|File deletion failed"),
    ("unlinkat", OUTCOME, "deleted|deleted", "filesystem", "file", "", "File deleted|File deletion failed"),
    ("rmdir", OUTCOME, "deleted|deleted", "filesystem", "directory", "", "Directory deleted|Directory deletion failed"),
    ("rename", OUTCOME, "modified|modified", "filesystem", "file", "", "File renamed|File rename failed"),
    ("renameat", OUTCOME, "modified|modified", "filesystem", "file", "", "File renamed|File rename failed"),
    ("renameat2", OUTCOME, "modified|modified", "filesystem", "file", "", "File renamed|File rename failed"),
    ("mkdir", OUTCOME, "created|created", "filesystem", "directory", "", "Directory created|Directory creation failed"),
    ("mkdirat", OUTCOME, "created|created", "filesystem", "directory", "", "Directory created|Directory creation failed"),
    ("link", OUTCOME, "created|created", "filesystem", "file", "", "Hard link created|Hard link creation failed"),
    ("linkat", OUTCOME, "created|created", "filesystem", "file", "", "Hard link created|Hard link creation failed"),
    ("symlink", OUTCOME, "created|created", "filesystem", "file", "", "Symbolic link created|Symbolic link creation failed"),
    ("symlinkat", OUTCOME, "created|created", "filesystem", "file", "", "Symbolic link created|Symbolic link creation failed"),
    ("mknod", OUTCOME, "created|created", "filesystem", "file", "", "Device node created|Device node creation failed"),
    ("mknodat", OUTCOME, "created|created", "filesystem", "file", "", "Device node created|Device node creation failed"),
] + [
    (sc, OUTCOME, "acl_modified|acl_modified", "filesystem", "file", "", "File permissions changed|File permission change failed")
    for sc in ("chmod", "fchmod", "fchmodat", "fchmodat2")
] + [
    (sc, OUTCOME, "acl_modified|acl_modified", "filesystem", "file", "", "File ownership changed|File ownership change failed")
    for sc in ("chown", "fchown", "lchown", "fchownat")
] + [
    (sc, OUTCOME, "acl_modified|acl_modified", "filesystem", "file", "",
     "File extended attributes changed|File extended attribute change failed")
    for sc in ("setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr")
] + [
    (sc, OUTCOME, "modified|modified", "filesystem", "file", "", "File timestamps changed|File timestamp change failed")
    for sc in ("utime", "utimes", "utimensat", "futimesat")
] + [
    # --- untagged classes: signature only
    ("init_module", OUTCOME, "", "", "", "", "Kernel module loaded|Kernel module load failed"),
    ("finit_module", OUTCOME, "", "", "", "", "Kernel module loaded|Kernel module load failed"),
    ("delete_module", OUTCOME, "", "", "", "", "Kernel module unloaded|Kernel module unload failed"),
]


# CIM status per class when it is not success / failure (Endpoint.Services uses
# started / stopped / critical). "success value|failure value".
STATUS = {
    "SERVICE_START": "started|critical",
    "SERVICE_STOP": "stopped|critical",
    "ANOM_LOGIN_FAILURES": "success",
    "DAEMON_ABORT": "failure",
}


def actions_rows():
    rows = []
    for key, outcome, action, change_type, category, result, signature in ACTIONS:
        status = STATUS.get(key, "success|failure")
        if outcome == OUTCOME:
            a_ok, a_fail = action.split("|") if action else ("", "")
            st_ok, st_fail = status.split("|")
            s_ok, s_fail = signature.split("|")
            rows.append([key, "success", a_ok, st_ok, change_type, category, result, s_ok])
            rows.append([key, "*", a_fail, st_fail, change_type, category, result, s_fail])
        else:
            rows.append([key, outcome, action, status, change_type, category, result, signature])
    return rows


def main():
    os.makedirs(LOOKUP_DIR, exist_ok=True)
    path = os.path.join(LOOKUP_DIR, "auditd_actions.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["auditd_action", "auditd_outcome", "action", "status", "change_type", "object_category", "result",
                    "signature"])
        rows = actions_rows()
        w.writerows(rows)
    print("wrote %s (%d rows)" % (path, len(rows)))

    path = os.path.join(LOOKUP_DIR, "auditd_record_types.csv")
    with open(AUDITBEAT_TYPES, encoding="utf-8") as src, open(path, "w", newline="") as f:
        r = csv.DictReader(src)
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["auditd_record_type", "auditd_record_type_id", "auditd_record_type_description"])
        n = 0
        for row in r:
            w.writerow([row["auditd_message_type"].upper(), row["auditd_message_type_id"],
                        row["auditd_message_type_description"]])
            n += 1
    print("wrote %s (%d rows)" % (path, n))


if __name__ == "__main__":
    main()
