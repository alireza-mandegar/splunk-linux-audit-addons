# SOC-TA-auditd: Linux auditd Add-on for Splunk

Search-time CIM normalization for the **Linux audit daemon log** (`/var/log/audit/audit.log`). Install it once and auditd
data populates the Splunk Common Information Model (CIM) data models, so Enterprise Security correlation searches, ESCU
detections and CIM dashboards work on Linux hosts. Field aliases, calculated fields, lookups, eventtypes and tags only:
there are no inputs, no scripts and no index-time field transforms.

## How events are built

The kernel writes one audit event as several records (`SYSCALL`, `EXECVE`, `CWD`, `PATH`, `SOCKADDR`, `PROCTITLE`, ...)
that share the id `msg=audit(<epoch>.<ms>:<serial>)`. The add-on keeps those records together: **one Splunk event = one
audit event**, so a process start carries its executable, user, full command line and working directory in one event.

* Consecutive records with the same id form one event; a new event starts where the id changes. If records of two
  events interleave, they are split, never mixed.
* Fields that occur in several records (`type`, `name`, `nametype`, ...) are multivalue, in record order.
* `auditd_record_type` names the event: the user-space or special record (`USER_LOGIN`, `CONFIG_CHANGE`, `AVC`, ...),
  otherwise `SYSCALL`.
* Hex-encoded values (paths, arguments and commands that contain spaces or special characters) are decoded into the
  CIM fields. The raw fields keep auditd's encoding.

## Supported versions

| Component | Supported |
|---|---|
| Linux audit userspace (auditd) | 2.8 and 3.x with **`log_format = ENRICHED`** (the default since 3.0). Any CPU architecture: syscall names come from the ENRICHED fields. |
| Splunk | Enterprise / Cloud 9.0 or later. Validated on Splunk Enterprise 10.6.1. |
| Splunk CIM add-on | 6.x and the ES-synced 8.x line. Validated with Splunk_SA_CIM 8.8.0. |
| Enterprise Security | Yes. Asset and identity fields (`*_bunit`, `*_category`, `*_priority`) are left to ES. |

With `log_format = RAW` the records are parsed and grouped and the user-space classes (logons, account changes, services,
audit configuration, packages) are mapped, but users are numeric ids and the syscall classes (processes, files, network)
are not tagged, because RAW records carry syscall numbers instead of names.

## CIM coverage

| CIM data model / dataset | auditd source | Eventtype | Tags |
|---|---|---|---|
| Endpoint.Processes | `SYSCALL` `execve` / `execveat`; sudo `USER_CMD` | `auditd_process_start`, `auditd_user_cmd` | process report |
| Endpoint.Ports | `SYSCALL` `bind` on IPv4/IPv6 with port ≠ 0 | `auditd_socket_bind` | listening port |
| Endpoint.Services | `SERVICE_START`, `SERVICE_STOP` (systemd) | `auditd_service_start`, `_stop` | service report |
| Endpoint.Filesystem | file syscalls that recorded a `PATH` item (watches) | `auditd_file_access` | endpoint filesystem |
| Authentication | `USER_LOGIN`; `USER_AUTH` from programs other than sshd/login | `auditd_user_login`, `auditd_user_auth` | authentication |
| Authentication.Privileged_Authentication | `USER_AUTH` from sudo, sudoedit, su, runuser, pkexec, doas | `auditd_privileged_auth` | authentication privileged |
| Change.Account_Management | `ADD_USER`, `DEL_USER`, `USER_MGMT`, `USER_CHAUTHTOK`, `ACCT_LOCK`, `ACCT_UNLOCK`, `ROLE_ASSIGN`, `ROLE_REMOVE`, `ANOM_LOGIN_FAILURES`, `ADD_GROUP`, `DEL_GROUP`, `GRP_MGMT`, `GRP_CHAUTHTOK` | `auditd_user_change`, `auditd_group_change` | change account |
| Change.Endpoint_Changes (+ Endpoint_Restarts) | `SOFTWARE_UPDATE` (rpm/dnf), `SYSTEM_BOOT`, `SYSTEM_SHUTDOWN` | `auditd_software_change`, `auditd_system_boot`, `auditd_system_shutdown` | change endpoint |
| Change.Auditing_Changes | `CONFIG_CHANGE`, `DAEMON_START`, `DAEMON_END`, `DAEMON_ABORT` | `auditd_audit_change` | change audit |
| Network_Traffic | `SYSCALL` `connect`, `accept`, `accept4` on IPv4/IPv6 | `auditd_socket_connection` | network communicate |

Untagged eventtypes, for searches: `auditd_user_auth_login_apps` (sshd/login `USER_AUTH`), `auditd_session` (PAM
account, credential and session records, `LOGIN`), `auditd_mac_denial` (SELinux/AppArmor `AVC`), `auditd_anomaly`
(`ANOM_ABEND`, `ANOM_PROMISCUOUS`, ...), `auditd_kernel_module` (`init_module`, `finit_module`, `delete_module`).

Design decisions:

* **One Authentication record per logon.** An SSH password logon writes `USER_AUTH` and `USER_LOGIN`. The add-on tags
  `USER_LOGIN`, plus `USER_AUTH` from programs that write no `USER_LOGIN` (sudo, su, vsftpd, ...). OpenSSH 9.8+ runs
  PAM in `sshd-session` (and `sshd-auth` in 10.x); those are treated like `sshd`.
* **Files go to Endpoint.Filesystem only.** The CIM `Change` model excludes `object_category=file|directory`.
* **The file of a file event** is the `PATH` item with nametype `CREATE`, else `DELETE`, `NORMAL`, `UNKNOWN`, then any
  other item, and the parent directory only when nothing else was recorded. A rename reports the new name. Relative
  names are joined with the `CWD` record.
* **`open`/`openat` are split by access mode**: `created` when a `PATH` item says `CREATE`, `modified` when the flags ask
  for write access, create, truncate or append, otherwise `read`.
* **sudo `USER_CMD`** describes the command sudo ran: `process` is the command line and sudo is the parent process.
* **A non-blocking `connect()`** returns `EINPROGRESS` (`success=no exit=-115`) although the connection proceeds; it is
  counted as allowed.

## Known gaps

| Model | Field(s) | Reason / workaround |
|---|---|---|
| Endpoint.Processes | `parent_process`, `parent_process_name`, `parent_process_path` (execve) | The `SYSCALL` record only holds the parent pid (`ppid`). Join on `parent_process_id` if you need them. |
| Endpoint.Processes | `process_hash`, `process_guid` | Not in audit records. |
| Endpoint.Processes | `process_integrity_level` | Heuristic (Linux has no integrity levels): root without a login session (`auid` unset) = `system`, other root = `high`, any other user = `medium`. |
| Endpoint.Ports | `transport`, `src` | `bind` reveals neither the transport nor a remote side. `state=listening` is an approximation: bind does not prove `listen()`. |
| Endpoint.Services | `service_path`, `start_mode`, `description` | systemd's `SERVICE_*` records only contain the unit name. |
| Endpoint.Filesystem | `file_hash`, `file_size`, file times | Not in audit records. |
| Authentication | `authentication_method` beyond `PAM`, `reason` | sshd does not record password vs. public key in audit records. |
| Change | `object_path`, `*_nt_domain` | Not applicable to Linux accounts. |
| Change.Endpoint_Changes | Debian/Ubuntu packages | dpkg/apt write no `SOFTWARE_UPDATE` records. Watch `/var/lib/dpkg/` or use the Auditbeat add-on's system/package dataset. |
| Network_Traffic | `transport` for `connect`, bytes/packets, local address and port | Not in the records of these syscalls. |
| Network_Traffic | `app` | Carries the process name: a host sensor cannot see the application protocol. |
| Inventory | all | auditd has no state snapshots. |

## Installation

| Splunk tier | Install? | What it does there |
|---|---|---|
| Search heads (incl. ES search heads, SHC via deployer) | **Required** | All search-time knowledge: field extraction, aliases, calculated fields, lookups, eventtypes, tags |
| Indexers (incl. via cluster manager) | **Required** | Event breaking (records grouped per audit event), timestamp, `TRUNCATE` |
| Heavy forwarders | Required if they parse the data before the indexers | Same as indexers |
| Universal forwarders | Recommended | `EVENT_BREAKER_*`, so load balancing never splits an audit event between indexers |
| Splunk Cloud | Install on the search head stack; the parsing settings are applied to the indexers by Splunk Cloud | |

The add-on has no inputs and no `local/` configuration, so it is safe on every tier. All knowledge objects are exported to
`system` (`metadata/default.meta`).

### Sourcetype and index

* Sourcetype: **`auditd`**. This is also the sourcetype of the ESCU `linux_auditd` macro, so the ESCU *Linux Auditd*
  detections search this data without changes. Because one Splunk event holds every record of an audit event, a
  search that counts or groups by `type` sees one row per audit event, not per record.
* Index: any. Set it in the **`auditd_index`** macro (`local/macros.conf`, default `index=auditd`); the macro is used by
  the validation searches below. Eventtypes do not restrict the index.
* **Add the index to the CIM index allowlists** (CIM Setup page, or the `cim_Endpoint_indexes`,
  `cim_Authentication_indexes`, `cim_Change_indexes`, `cim_Network_Traffic_indexes` macros), then rebuild the
  accelerations.
* The Splunk Add-on for Unix and Linux also uses the name `auditd` for the output of its `rlog.sh` scripted input
  (`ausearch -i`, a different format). Leave that input disabled when you monitor `audit.log` with this add-on.

### Getting the data in

1. **auditd.conf** (`/etc/audit/auditd.conf`), then `service auditd restart` (RHEL and its rebuilds refuse
   `systemctl restart auditd`):

   ```ini
   log_format = ENRICHED      # names next to numeric ids; required for the syscall classes
   name_format = hostname     # optional: adds node=<host> to every record (used for dest)
   log_group = splunkfwd      # optional: lets the forwarder's group read the log (see below)
   ```

2. **Read access.** `/var/log/audit/` is readable by root only. Either run the universal forwarder with read access to
   it, or set `log_group` to the forwarder's group and open the directory to that group:

   ```bash
   chgrp splunkfwd /var/log/audit && chmod 0750 /var/log/audit
   ```

3. **inputs.conf** on the universal forwarder:

   ```ini
   [monitor:///var/log/audit/audit.log]
   sourcetype = auditd
   index = auditd
   disabled = false
   ```

Records forwarded through syslog also work (the timestamp and the grouping come from `msg=audit(...)`, not from the
syslog header), as long as the relay keeps the 0x1D separator: turn off control-character escaping in rsyslog
(`$EscapeControlCharactersOnReceive off`), otherwise it is written as `#035`.

## Recommended audit rules

Put the rules in `/etc/audit/rules.d/splunk.rules` and load them with `augenrules --load`. Execve rules produce the
most data; scope them (for example `-F auid>=1000 -F auid!=unset` for interactive users only) if volume matters.

```text
# Process execution -> Endpoint.Processes
-a always,exit -F arch=b64 -S execve,execveat -k exec
-a always,exit -F arch=b32 -S execve -k exec
# Network -> Network_Traffic (connect/accept) and Endpoint.Ports (bind)
-a always,exit -F arch=b64 -S connect -F a2=16 -k net_connect
-a always,exit -F arch=b64 -S connect -F a2=28 -k net_connect
-a always,exit -F arch=b64 -S accept,accept4 -k net_accept
-a always,exit -F arch=b64 -S bind -k net_bind
# Identity and privilege files -> Endpoint.Filesystem
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p rwa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/cron.d/ -p wa -k cron
# Audit configuration tampering -> Change.Auditing_Changes (plus CONFIG_CHANGE, always logged)
-w /etc/audit/ -p wa -k auditconfig
-w /sbin/auditctl -p x -k audittools
# Kernel modules (auditd_kernel_module eventtype)
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
# USER_LOGIN, USER_AUTH, ADD_USER, SERVICE_START, SOFTWARE_UPDATE, ... are user-space
# records and need no rules.
```

`-F a2=16` / `-F a2=28` limit `connect` to IPv4 / IPv6 socket address sizes, which drops the much more frequent Unix
socket connections.

## Contents

```
SOC-TA-auditd/
  app.manifest
  README.md
  LICENSE.txt
  default/app.conf
  default/props.conf         sourcetype auditd: event breaking, REPORT, EVAL, FIELDALIAS, LOOKUP
  default/transforms.conf    search-time extractions and lookup definitions (no index-time transforms)
  default/eventtypes.conf    21 eventtypes, one per audit event class
  default/tags.conf          CIM constraint tags
  default/macros.conf        `auditd_index`, `auditd`
  lookups/auditd_actions.csv        event class -> action, status, change_type, object_category, result, signature
  lookups/auditd_record_types.csv   record type -> numeric ID and description (217 types)
  metadata/default.meta      export = system
  samples/                   SYNTHETIC audit.log records   [repository only, not packaged]
```

Helper fields added at search time:

| Field | Meaning |
|---|---|
| `auditd_record_type` | The record that names the event (`SYSCALL`, `USER_LOGIN`, `CONFIG_CHANGE`, ...) |
| `auditd_action` | Event class: the record type, or the syscall name (`open:read`, `open:modified`, `open:created` for opens) |
| `auditd_outcome` | `success`, `failure` or `unknown` |
| `auditd_event_id` | `<epoch>.<ms>:<serial>`, the id shared by the records |
| `auditd_record_type_id`, `auditd_record_type_description` | From `auditd_record_types.csv` |
| `auditd_execve_args`, `auditd_proctitle_raw`, `auditd_raw_exe`, `auditd_raw_comm`, `auditd_raw_cwd`, `auditd_raw_acct`, `auditd_raw_cmd` | Raw values with auditd's encoding kept |
| `auditd_file_raw`, `auditd_file_nametype`, `auditd_file_mode`, `auditd_file_owner`, `auditd_file_group` | The `PATH` item chosen as the file |

## Validation searches

Endpoint has several root datasets, so name each one:

```spl
| tstats count from datamodel=Endpoint.Processes by sourcetype, nodename
| tstats count from datamodel=Endpoint.Ports by sourcetype, nodename
| tstats count from datamodel=Endpoint.Services by sourcetype, nodename
| tstats count from datamodel=Endpoint.Filesystem by sourcetype, nodename
| tstats count from datamodel=Authentication by sourcetype, nodename
| tstats count from datamodel=Change by sourcetype, nodename
| tstats count from datamodel=Network_Traffic by sourcetype, nodename
```

```spl
| datamodel Endpoint Processes search | search sourcetype=auditd
| table _time Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.process_id Processes.parent_process_id Processes.process_current_directory Processes.action

| datamodel Endpoint Filesystem search | search sourcetype=auditd
| table _time Filesystem.dest Filesystem.action Filesystem.file_path Filesystem.file_name Filesystem.file_acl Filesystem.user Filesystem.process

| datamodel Authentication Authentication search | search sourcetype=auditd
| table _time Authentication.action Authentication.app Authentication.src Authentication.dest Authentication.user Authentication.src_user Authentication.signature

| datamodel Change Account_Management search | search sourcetype=auditd
| table _time All_Changes.action All_Changes.user All_Changes.src_user All_Changes.object All_Changes.object_category All_Changes.object_attrs All_Changes.command All_Changes.dest

| datamodel Network_Traffic All_Traffic search | search sourcetype=auditd
| table _time All_Traffic.action All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.direction All_Traffic.app All_Traffic.user
```

Event-class check (every class, its eventtypes and tags):

```spl
`auditd` | stats count by auditd_record_type auditd_action auditd_outcome action eventtype tag
```

Grouping check (every event should hold exactly one audit id):

```spl
`auditd` | rex max_match=0 "msg=audit\((?<ids>[\d.]+:\d+)\)" | eval ids=mvcount(mvdedup(ids)) | stats count by ids
```

## Validation status (1.0.0)

Validated on **Splunk Enterprise 10.6.1** (`splunk/splunk` Docker image) with **Splunk_SA_CIM 8.8.0**, using the
synthetic samples (189 records, 79 audit events).

* `splunk btool check`: no errors.
* Parsing: 79/79 events, no event with two audit ids, `_time` equal to the `msg=audit` timestamp to the millisecond. A
  5 MB file (22,317 records) indexed as 9,159 events: every event complete, none mixed.

| Dataset | Sample events | Populated CIM fields | Empty (data not in audit records) |
|---|---|---|---|
| Endpoint.Processes | 8 | action, dest, user, user_id, process, process_name, process_exec, process_path, process_id, process_current_directory, process_integrity_level, parent_process_id; for sudo `USER_CMD` also parent_process_name/exec/path, parent_user | process_hash, process_guid, parent_process (execve) |
| Endpoint.Ports | 2 | dest, dest_port, state, user, process_id, creation_time | transport, src |
| Endpoint.Services | 3 | dest, service, service_name, service_id, status, user, process_id | service_path, start_mode, description |
| Endpoint.Filesystem | 11 | action, dest, file_path, file_name, file_acl, user, process, process_name, process_path, process_id, parent_process_id, image | file_hash, file_size, file times |
| Authentication (+ Failed 4, Privileged 2) | 8 | action, app, src, dest, user, user_id, src_user, signature, signature_id, session_id, process, authentication_method | reason, duration |
| Change.Account_Management (Created 2, Deleted 2, Updated 2, Lockouts 2) | 8 | action, status, change_type, object, object_id, object_attrs, object_category, command, user, user_name, src_user, src_user_name, src, dest, dvc | object_path, *_nt_domain |
| Change.Endpoint_Changes (Restarts 1) | 5 | action, status, change_type, object, object_attrs, object_category, command, user, src, dest, dvc | object_id, object_path |
| Change.Auditing_Changes | 5 | action, status, change_type, object, object_attrs, object_category, command, user, src, dest, dvc | object_id, object_path |
| Network_Traffic (Allowed 3, Blocked 1) | 4 | action, src, src_ip, src_port, dest, dest_ip, dest_port, transport, protocol, protocol_version, direction, app, user, process_id, session_id, dvc | bytes, packets, duration |

## Development

The repository folder `auditd/tools/` (not part of the package):

* `generate_samples.py` regenerates `samples/` (synthetic records).
* `generate_lookups.py` regenerates both lookups (`auditd_actions.csv` from its embedded table).
* `validate_splunk.py --load` indexes the samples into a running Splunk and writes the field-population report.

From the repository root, `python3 tools/check_conf.py auditd/SOC-TA-auditd` runs the static conf check and
`sh tools/build_package.sh auditd` builds the package (without `samples/`).
