#!/usr/bin/env python3
"""Generate the SOC-TA-auditbeat lookup tables.

auditbeat_actions.csv
    Built from the ACTIONS table below (the single source of truth for the
    action / status / change_type / object_category / result / signature of
    every Auditbeat event class; see the add-on README). Rows marked
    OUTCOME are expanded into a "success" row and a "*" (any other outcome)
    row. Specific rows come before wildcard rows because the lookup uses
    WILDCARD(auditbeat_outcome) with max_matches = 1.

auditd_message_types.csv
    Every record type known to go-libaudit v2.6.2 (auparse/zaudit_msg_types.go)
    with its numeric ID and the description from the kernel's
    include/uapi/linux/audit.h or audit-userspace lib/audit-records.h.

Usage:
    python3 auditbeat/tools/generate_lookups.py <zaudit_msg_types.go> <audit-records.h> <linux/audit.h> [normalizations.yaml]

Sources used for the shipped CSV:
    go-libaudit v2.6.2  auparse/zaudit_msg_types.go, aucoalesce/normalizations.yaml
    audit-userspace v4.0.2  lib/audit-records.h
    Linux v6.8  include/uapi/linux/audit.h
"""

import csv
import os
import re
import sys

LOOKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SOC-TA-auditbeat", "lookups")

OUTCOME = "OUTCOME"  # expand into success / failure rows

# (event.module, auditbeat_dataset, auditbeat_action, outcome, action, change_type, object_category, result, signature)
# For OUTCOME rows: action may be "success_value|failure_value"; signature may be "success text|failure text".
ACTIONS = [
    # --- auditd: process execution
    ("auditd", "auditd", "executed", OUTCOME, "allowed|blocked", "", "", "", "Process executed|Process execution failed"),
    ("auditd", "auditd", "ran-command", OUTCOME, "allowed|blocked", "", "", "", "Command run via sudo|Command via sudo failed"),
    # --- auditd: network
    ("auditd", "auditd", "connected-to", OUTCOME, "allowed|blocked", "", "", "",
     "Outbound network connection|Outbound network connection failed"),
    ("auditd", "auditd", "accepted-connection-from", OUTCOME, "allowed|blocked", "", "", "",
     "Inbound network connection accepted|Inbound network connection failed"),
    ("auditd", "auditd", "bound-socket", OUTCOME, "", "", "", "", "Socket bound to local address|Socket bind failed"),
    ("auditd", "auditd", "listen-for-connections", OUTCOME, "", "", "", "", "Socket listening for connections|Socket listen failed"),
    # --- auditd: authentication and sessions
    ("auditd", "auditd", "authenticated", OUTCOME, "success|failure", "", "", "", "PAM authentication succeeded|PAM authentication failed"),
    ("auditd", "auditd", "logged-in", OUTCOME, "success|failure", "", "", "", "User logged in|User login failed"),
    ("auditd", "auditd", "logged-out", OUTCOME, "logoff|logoff", "", "", "", "User logged out|User logout failed"),
    ("auditd", "auditd", "was-authorized", OUTCOME, "success|failure", "", "", "",
     "PAM account authorization succeeded|PAM account authorization failed"),
    ("auditd", "auditd", "error", OUTCOME, "failure|failure", "", "", "", "User authentication error|User authentication error"),
    ("auditd", "auditd", "acquired-credentials", OUTCOME, "", "", "", "", "PAM credentials acquired|PAM credentials acquisition failed"),
    ("auditd", "auditd", "refreshed-credentials", OUTCOME, "", "", "", "", "PAM credentials refreshed|PAM credentials refresh failed"),
    ("auditd", "auditd", "disposed-credentials", OUTCOME, "", "", "", "", "PAM credentials disposed|PAM credentials disposal failed"),
    ("auditd", "auditd", "started-session", OUTCOME, "", "", "", "", "Session opened|Session open failed"),
    ("auditd", "auditd", "ended-session", OUTCOME, "", "", "", "", "Session closed|Session close failed"),
    ("auditd", "auditd", "changed-login-id-to", OUTCOME, "", "", "", "", "Login UID assigned|Login UID assignment failed"),
    # --- auditd: account management
    ("auditd", "auditd", "added-user-account", OUTCOME, "created|created", "AAA", "user", "",
     "User account created|User account creation failed"),
    ("auditd", "auditd", "deleted-user-account", OUTCOME, "deleted|deleted", "AAA", "user", "",
     "User account deleted|User account deletion failed"),
    ("auditd", "auditd", "modified-user-account", OUTCOME, "modified|modified", "AAA", "user", "",
     "User account modified|User account modification failed"),
    ("auditd", "auditd", "changed-password", OUTCOME, "modified|modified", "AAA", "user", "",
     "User password changed|User password change failed"),
    ("auditd", "auditd", "locked-account", OUTCOME, "lockout|lockout", "AAA", "user", "lockout",
     "User account locked|User account lock failed"),
    ("auditd", "auditd", "unlocked-account", OUTCOME, "unlocked|unlocked", "AAA", "user", "",
     "User account unlocked|User account unlock failed"),
    ("auditd", "auditd", "failed-log-in-too-many-times-to", OUTCOME, "lockout|lockout", "AAA", "user", "lockout",
     "Account locked after too many failed logins|Account locked after too many failed logins"),
    ("auditd", "auditd", "assigned-user-role-to", OUTCOME, "modified|modified", "AAA", "user", "",
     "Role assigned to user|Role assignment failed"),
    ("auditd", "auditd", "removed-user-role-from", OUTCOME, "modified|modified", "AAA", "user", "",
     "Role removed from user|Role removal failed"),
    ("auditd", "auditd", "added-group-account-to", OUTCOME, "created|created", "AAA", "group", "",
     "Group created|Group creation failed"),
    ("auditd", "auditd", "deleted-group-account-from", OUTCOME, "deleted|deleted", "AAA", "group", "",
     "Group deleted|Group deletion failed"),
    ("auditd", "auditd", "modified-group-account", OUTCOME, "modified|modified", "AAA", "group", "",
     "Group modified|Group modification failed"),
    ("auditd", "auditd", "changed-group-password", OUTCOME, "modified|modified", "AAA", "group", "",
     "Group password changed|Group password change failed"),
    # --- auditd: services (Services.status: started / stopped / critical)
    ("auditd", "auditd", "started-service", "success", "started", "", "service", "", "Service started", "started"),
    ("auditd", "auditd", "started-service", "*", "started", "", "service", "", "Service failed to start", "critical"),
    ("auditd", "auditd", "stopped-service", "success", "stopped", "", "service", "", "Service stopped", "stopped"),
    ("auditd", "auditd", "stopped-service", "*", "stopped", "", "service", "", "Service stopped with failure", "critical"),
    # --- auditd: audit subsystem (Change.Auditing_Changes)
    ("auditd", "auditd", "changed-audit-configuration", OUTCOME, "modified|modified", "audit", "audit_rule", "",
     "Audit configuration changed|Audit configuration change failed"),
    ("auditd", "auditd", "started-audit", OUTCOME, "started|started", "audit", "service", "",
     "Audit daemon started|Audit daemon start failed"),
    ("auditd", "auditd", "shutdown-audit", OUTCOME, "stopped|stopped", "audit", "service", "",
     "Audit daemon stopped|Audit daemon stop failed"),
    # --- auditd: system state
    ("auditd", "auditd", "booted-system", OUTCOME, "modified|modified", "restart", "host", "", "System booted|System boot failed"),
    ("auditd", "auditd", "shutdown-system", OUTCOME, "stopped|stopped", "shutdown", "host", "",
     "System shutdown|System shutdown failed"),
    # --- auditd: file watches (Endpoint.Filesystem). opened-file is split by open flags in props.conf.
    ("auditd", "auditd", "opened-file:read", OUTCOME, "read|read", "filesystem", "file", "",
     "File opened for reading|File open for reading failed"),
    ("auditd", "auditd", "opened-file:modified", OUTCOME, "modified|modified", "filesystem", "file", "",
     "File opened for writing|File open for writing failed"),
    ("auditd", "auditd", "opened-file:created", OUTCOME, "created|created", "filesystem", "file", "",
     "File created|File creation failed"),
    ("auditd", "auditd", "read-file", OUTCOME, "read|read", "filesystem", "file", "", "File read|File read failed"),
    ("auditd", "auditd", "wrote-to-file", OUTCOME, "modified|modified", "filesystem", "file", "", "File written|File write failed"),
    ("auditd", "auditd", "changed-file-attributes-of", OUTCOME, "acl_modified|acl_modified", "filesystem", "file", "",
     "File extended attributes changed|File extended attribute change failed"),
    ("auditd", "auditd", "changed-file-permissions-of", OUTCOME, "acl_modified|acl_modified", "filesystem", "file", "",
     "File permissions changed|File permission change failed"),
    ("auditd", "auditd", "changed-file-ownership-of", OUTCOME, "acl_modified|acl_modified", "filesystem", "file", "",
     "File ownership changed|File ownership change failed"),
    ("auditd", "auditd", "changed-timestamp-of", OUTCOME, "modified|modified", "filesystem", "file", "",
     "File timestamps changed|File timestamp change failed"),
    ("auditd", "auditd", "created-directory", OUTCOME, "created|created", "filesystem", "directory", "",
     "Directory created|Directory creation failed"),
    ("auditd", "auditd", "linked", OUTCOME, "created|created", "filesystem", "file", "", "Hard link created|Hard link creation failed"),
    ("auditd", "auditd", "symlinked", OUTCOME, "created|created", "filesystem", "file", "",
     "Symbolic link created|Symbolic link creation failed"),
    ("auditd", "auditd", "make-device", OUTCOME, "created|created", "filesystem", "file", "", "Device node created|Device node creation failed"),
    ("auditd", "auditd", "deleted", OUTCOME, "deleted|deleted", "filesystem", "file", "", "File deleted|File deletion failed"),
    ("auditd", "auditd", "renamed", OUTCOME, "modified|modified", "filesystem", "file", "", "File renamed|File rename failed"),
    # --- file_integrity (auditbeat_action is the collapsed action, see props.conf)
    ("file_integrity", "file", "created", "*", "created", "filesystem", "file", "", "File created", "success"),
    ("file_integrity", "file", "updated", "*", "modified", "filesystem", "file", "", "File modified", "success"),
    ("file_integrity", "file", "moved", "*", "modified", "filesystem", "file", "", "File moved or renamed", "success"),
    ("file_integrity", "file", "deleted", "*", "deleted", "filesystem", "file", "", "File deleted", "success"),
    ("file_integrity", "file", "attributes_modified", "*", "acl_modified", "filesystem", "file", "",
     "File permissions or attributes changed", "success"),
    ("file_integrity", "file", "initial_scan", "*", "", "", "", "", "File found during initial scan", ""),
    # --- system/process
    ("system", "process", "process_started", "*", "allowed", "", "", "", "Process started", "success"),
    ("system", "process", "process_ran", "*", "allowed", "", "", "", "Process ran", "success"),
    ("system", "process", "process_changed_image", "*", "allowed", "", "", "", "Process executed a new image", "success"),
    ("system", "process", "process_stopped", "*", "", "", "", "", "Process stopped", ""),
    ("system", "process", "existing_process", "*", "", "", "", "", "Process running (state)", ""),
    ("system", "process", "process_error", "*", "", "", "", "", "Process monitoring error", "failure"),
    # --- system/socket
    ("system", "socket", "network_flow", "*", "allowed", "", "", "", "Network flow", "success"),
    # --- system/login
    ("system", "login", "user_login", "success", "success", "", "", "", "User logged in", "success"),
    ("system", "login", "user_login", "*", "failure", "", "", "", "User login failed", "failure"),
    ("system", "login", "user_logout", "*", "logoff", "", "", "", "User logged out", "success"),
    ("system", "login", "boot", "*", "modified", "restart", "host", "", "System booted", "success"),
    ("system", "login", "shutdown", "*", "stopped", "shutdown", "host", "", "System shutdown", "success"),
    # --- system/user
    ("system", "user", "user_added", "*", "created", "AAA", "user", "", "User account created", "success"),
    ("system", "user", "user_removed", "*", "deleted", "AAA", "user", "", "User account removed", "success"),
    ("system", "user", "user_changed", "*", "modified", "AAA", "user", "", "User account changed", "success"),
    ("system", "user", "password_changed", "*", "modified", "AAA", "user", "", "User password changed", "success"),
    ("system", "user", "existing_user", "*", "", "", "", "", "Existing user account (state)", ""),
    # --- system/package
    ("system", "package", "package_installed", "*", "created", "software", "package", "", "Package installed", "success"),
    ("system", "package", "package_removed", "*", "deleted", "software", "package", "", "Package removed", "success"),
    ("system", "package", "package_updated", "*", "updated", "software", "package", "", "Package updated", "success"),
    ("system", "package", "existing_package", "*", "", "", "", "", "Installed package (state)", ""),
    # --- system/host
    ("system", "host", "host", "*", "", "", "", "", "Host information (state)", ""),
    ("system", "host", "reboot", "*", "modified", "restart", "host", "", "Host rebooted", "success"),
    ("system", "host", "hostname_changed", "*", "modified", "configuration", "host", "", "Hostname changed", "success"),
    ("system", "host", "host_id_changed", "*", "modified", "configuration", "host", "", "Host ID changed", "success"),
    ("system", "host", "host_changed", "*", "modified", "configuration", "host", "", "Host configuration changed", "success"),
]

HEADER = ["event_module", "auditbeat_dataset", "auditbeat_action", "auditbeat_outcome",
          "action", "status", "change_type", "object_category", "result", "signature"]


def expand(row):
    module, dataset, key, outcome, action, change_type, obj_cat, result, signature = row[:9]
    if outcome != OUTCOME:
        status = row[9]
        return [[module, dataset, key, outcome, action, status, change_type, obj_cat, result, signature]]
    act_ok, act_fail = (action.split("|") + [""])[:2] if action else ("", "")
    sig_ok, sig_fail = signature.split("|")
    return [
        [module, dataset, key, "success", act_ok, "success", change_type, obj_cat, result, sig_ok],
        [module, dataset, key, "*", act_fail, "failure", change_type, obj_cat, result, sig_fail],
    ]


def write_actions():
    rows = [r for row in ACTIONS for r in expand(row)]
    seen = set()
    for r in rows:
        k = tuple(r[:4])
        if k in seen:
            raise SystemExit("duplicate lookup key: %r" % (k,))
        seen.add(k)
    path = os.path.join(LOOKUP_DIR, "auditbeat_actions.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(HEADER)
        w.writerows(rows)
    print("auditbeat_actions.csv      %d rows" % len(rows))


def read_descriptions(paths):
    """C headers: '#define AUDIT_X 1234 /* desc */'; normalizations.yaml: '# AUDIT_X - desc'."""
    desc = {}
    c_pat = re.compile(r"^#define\s+AUDIT_([A-Z0-9_]+)\s+(\d+)\s*/\*\s*(.*?)\s*\*/")
    yaml_pat = re.compile(r"^\s*#\s*AUDIT_([A-Z0-9_]+)\s+-\s+(.*?)\s*$")
    for p in paths:
        for line in open(p, encoding="utf-8", errors="replace"):
            m = c_pat.match(line)
            if m:
                name, text = m.group(1), m.group(3)
            else:
                m = yaml_pat.match(line)
                if not m:
                    continue
                name, text = m.group(1), m.group(2)
            if name not in desc and text:
                desc[name] = text.rstrip(" .")
    return desc


def write_message_types(go_table, header_paths):
    desc = read_descriptions(header_paths)
    pat = re.compile(r"^\s*AUDIT_([A-Z0-9_]+)\s+AuditMessageType\s*=\s*(\d+)")
    rows = []
    for line in open(go_table, encoding="utf-8"):
        m = pat.match(line)
        if m:
            name, num = m.group(1), int(m.group(2))
            if re.search(r"(^|_)(FIRST|LAST)(_|$)", name):
                continue  # range markers such as AUDIT_LAST_EVENT, not real record types
            rows.append([name.lower(), num, desc.get(name, name.replace("_", " ").capitalize())])
    path = os.path.join(LOOKUP_DIR, "auditd_message_types.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["auditd_message_type", "auditd_message_type_id", "auditd_message_type_description"])
        w.writerows(sorted(rows, key=lambda r: r[1]))
    missing = sum(1 for r in rows if r[2] == r[0].replace("_", " ").capitalize())
    print("auditd_message_types.csv   %d rows (%d without a header description)" % (len(rows), missing))


def main():
    os.makedirs(LOOKUP_DIR, exist_ok=True)
    write_actions()
    if len(sys.argv) >= 3:
        write_message_types(sys.argv[1], sys.argv[2:])
    else:
        print("auditd_message_types.csv   skipped (pass zaudit_msg_types.go and header files)")


if __name__ == "__main__":
    main()
