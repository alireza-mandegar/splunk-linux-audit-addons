# SOC-TA-auditbeat: Elastic Auditbeat Add-on for Splunk

Search-time CIM normalization for **Elastic Auditbeat** events in ECS JSON. Install it once and Auditbeat data populates the
Splunk Common Information Model (CIM) data models, so Enterprise Security correlation searches, ESCU detections and CIM
dashboards work on Linux hosts. The design follows `Splunk_TA_windows`: field aliases, calculated fields, lookups, eventtypes
and tags only. There are no inputs, no scripts and no index-time field transforms.

## Supported versions

| Component | Supported |
|---|---|
| Auditbeat | **8.19.x, 9.x**. Built against the v9.5.5 and v8.19.23 source; both ship go-libaudit v2.6.2. 7.6+ has the same field layout but is not tested. |
| Auditbeat modules | `auditd`; `file_integrity`; `system` datasets `host`, `login`, `package`, `process` (`procfs` and `kernel_tracing` backends), `socket`, `user` |
| Splunk | Enterprise / Cloud 9.0 or later (uses `mvmap`, `mvfind`, `in()`); validated on Splunk Enterprise 10.6.1 |
| Splunk CIM add-on | 6.x and the ES-synced 8.x line. Validated with Splunk_SA_CIM 6.1.0. |
| Enterprise Security | Yes. Asset and identity fields (`*_bunit`, `*_category`, `*_priority`) are left to ES. |

## CIM coverage

| CIM data model / dataset | Auditbeat source | Eventtype(s) | Tags |
|---|---|---|---|
| Endpoint.Processes | system/process `process_started`, `process_ran`, `process_changed_image`; auditd `execve` (`executed`); auditd sudo `USER_CMD` | `auditbeat_process_start`, `auditbeat_auditd_process_start`, `auditbeat_auditd_user_cmd` | process report |
| Endpoint.Ports | auditd `bind` on IPv4/IPv6 with port ≠ 0 | `auditbeat_auditd_socket_bind` | listening port |
| Endpoint.Services | auditd `SERVICE_START` / `SERVICE_STOP` (systemd) | `auditbeat_auditd_service_start`, `_stop` | service report |
| Endpoint.Filesystem | file_integrity (all actions except `initial_scan`); auditd file-watch syscalls | `auditbeat_fim_change`, `auditbeat_auditd_file_access` | endpoint filesystem |
| Authentication | auditd `USER_LOGIN`; auditd `USER_AUTH` from apps other than sshd/login | `auditbeat_auditd_user_login`, `auditbeat_auditd_user_auth` | authentication |
| Authentication.Privileged_Authentication | auditd `USER_AUTH` from sudo, sudoedit, su, runuser, pkexec, doas | `auditbeat_auditd_privileged_auth` | authentication privileged |
| Authentication (optional) | system/login `user_login` (wtmp/btmp) | `auditbeat_login_success`, `_failure` | authentication, **disabled by default** (see below) |
| Change.Account_Management | auditd `ADD_USER`, `DEL_USER`, `USER_MGMT`, `USER_CHAUTHTOK`, `ACCT_LOCK`/`UNLOCK`, `ROLE_*`, `ANOM_LOGIN_FAILURES`, `ADD_GROUP`, `DEL_GROUP`, `GRP_MGMT`, `GRP_CHAUTHTOK`; system/user changes | `auditbeat_auditd_user_change`, `auditbeat_auditd_group_change`, `auditbeat_user_change` | change account |
| Change.Endpoint_Changes (+ Endpoint_Restarts) | system/package install, remove, update; system/host reboot, hostname, host ID | `auditbeat_package_change`, `auditbeat_host_change` | change endpoint |
| Change.Auditing_Changes | auditd `CONFIG_CHANGE`, `DAEMON_START`, `DAEMON_END` | `auditbeat_auditd_audit_change` | change audit |
| Network_Traffic | system/socket flows; auditd `connect` / `accept` on IPv4/IPv6 | `auditbeat_socket_flow`, `auditbeat_auditd_socket_connection` | network communicate |
| Inventory (Compute_Inventory) OS + Network | system/host state events | `auditbeat_host_inventory` | inventory system version network |
| Inventory.User (+ Default_Accounts) | system/user state events (`root` is tagged `default`) | `auditbeat_user_inventory`, `auditbeat_user_inventory_default` | inventory user (default) |

Design decisions:

* **File integrity events go to Endpoint.Filesystem only.** The CIM `Change` model's root constraint excludes
  `object_category=file|directory|registry`, so file changes cannot be counted there.
* **One Authentication record per logon.** A password SSH logon produces auditd `USER_AUTH`, auditd `USER_LOGIN` and a wtmp record.
  The add-on tags `USER_LOGIN` and `USER_AUTH` from non-login apps (sudo, su, vsftpd, …). `USER_AUTH` from sshd/login and the wtmp
  records remain searchable through untagged eventtypes. OpenSSH 9.8+ runs PAM in `sshd-session` (and `sshd-auth` in 10.x);
  those are treated like `sshd`. **If you do not run the auditd module**, enable the system/login
  eventtypes in `local/tags.conf`:

  ```ini
  [eventtype=auditbeat_login_success]
  authentication = enabled

  [eventtype=auditbeat_login_failure]
  authentication = enabled
  ```
* **Packages go to Change, not Updates.** The Updates model describes patch requirements (advisory IDs, `available`/`installed`) from
  patch-management tools; Auditbeat only observes version changes after the fact.
* **Process starts only.** `process_stopped` and the `existing_process` state snapshots are not tagged; CIM's Processes dataset covers launches.

## Known gaps

| Model | Field(s) | Reason / workaround |
|---|---|---|
| Endpoint.Processes | `parent_process`, `parent_process_name`, `parent_process_path` | Auditbeat emits only `process.parent.pid`. Use the optional processor recipe below. |
| Endpoint.Processes | `process_hash` for auditd execve | Only system/process hashes executables. |
| Endpoint.Processes | `process_integrity_level` | Heuristic (Linux has no integrity levels): root without a login session = `system`, other root = `high`, any other user = `medium`. |
| Endpoint.Ports | `transport`, `src`, `src_port` | bind records carry neither the transport nor a remote side. `state=listening` is an approximation: bind does not prove `listen()`. |
| Endpoint.Services | `service_path`, `start_mode`, `description` | systemd's `SERVICE_*` records only contain the unit name. |
| Endpoint.Filesystem | `user` (fsnotify backend), `file_access_time`; `file_hash`/`file_size` for auditd watches | Use `backend: ebpf` (or `kprobes`) in file_integrity for the acting process and user. |
| Endpoint.Filesystem | `file_create_time` | Linux reports no birth time; for newly created files the add-on uses `mtime`. |
| Authentication | `authentication_method` beyond `PAM`, `reason` | Not in audit records (sshd does not log password vs publickey to auditd). |
| Change | `user`/`command` for package and host changes, `object_path`, `*_nt_domain` | State-diff datasets have no actor. |
| Network_Traffic | `transport` for auditd `connect`, local IP and port for auditd, bytes/packets for auditd, MAC/NAT/zone/rule/TCP flags | Not visible to kernel socket hooks; use system/socket for volumes. |
| Network_Traffic | `app` | Carries the process name: a host sensor cannot see the application protocol. |
| Inventory | `dns`, `interface`, `password`, CPU/Memory/Storage | Not collected by Auditbeat (use Metricbeat for hardware inventory). |

Unit notes: CIM `file_size` is in **kilobytes** (Auditbeat reports bytes); `duration` is in seconds (Auditbeat reports nanoseconds).

## Installation

| Splunk tier | Install? | What it does there |
|---|---|---|
| Search heads (incl. ES search heads, SHC via deployer) | **Required** | All search-time knowledge: field extraction, aliases, calculated fields, lookups, eventtypes, tags |
| Indexers (incl. via cluster manager) | **Required** when data arrives as a raw stream (file monitor, HEC `/raw`, TCP, Kafka raw) | Line breaking, timestamp extraction, `TRUNCATE` |
| Heavy forwarders | Required if they parse the data before the indexers | Same as indexers |
| Universal forwarders | Optional | `EVENT_BREAKER_*` for clean load balancing when monitoring Auditbeat's file output |
| Splunk Cloud | Install on the search head stack; the parsing settings are applied to the indexers by Splunk Cloud | |

The add-on has no inputs and no `local/` configuration, so it is safe on every tier. All knowledge objects are exported to
`system` (`metadata/default.meta`).

### Sourcetype and index

* Sourcetype: **`auditbeat`**. Every module uses this sourcetype; eventtypes split the event classes.
* Index: any. Set it in the **`auditbeat_index`** macro (`local/macros.conf`, default `index=auditbeat`); the macro is used by
  the validation searches below. Eventtypes do not restrict the index.
* **Add the index to the CIM index allowlists** (CIM Setup page, or the `cim_Endpoint_indexes`, `cim_Authentication_indexes`,
  `cim_Change_indexes`, `cim_Network_Traffic_indexes`, `cim_Compute_Inventory_indexes` macros), then rebuild the accelerations.
* Do **not** set `INDEXED_EXTRACTIONS = json` for this sourcetype; the add-on uses `KV_MODE = json` and indexed extraction would
  duplicate every field.
* Large auditd events: Splunk's automatic JSON extraction stops at `[kv] maxchars` (`limits.conf`, default 10240 bytes). Keep
  `include_raw_message: false` in Auditbeat (the default) so events stay well below that.

### Getting the data in

The add-on expects the **unchanged Auditbeat JSON document as the event body (`_raw`)**, one document per event. Auditbeat has no
native Splunk output; common paths:

| Path | Notes |
|---|---|
| Auditbeat `output.file` → universal forwarder | Simplest. All `props.conf` parsing settings apply. Example below. |
| Auditbeat → Logstash → Splunk TCP input | `tcp { codec => json_lines }` output into a Splunk `[tcp://…]` input with `sourcetype = auditbeat`. Parsing settings apply. |
| Auditbeat → Logstash/Kafka → HEC `/services/collector/raw` | One JSON document per line; parsing settings apply. Do not send JSON arrays (`json_batch`) to `/raw`. |
| … → HEC `/services/collector/event` | The Auditbeat document must be the HEC `"event"` object. Line breaking, `TIME_*` and `TRUNCATE` are **ignored**: `_time` comes from the HEC `"time"` field (or index time). Set `"time"` from `@timestamp`, or append `?auto_extract_timestamp=true` to the URL so Splunk applies `TIME_PREFIX`/`TIME_FORMAT`. |

File output + universal forwarder:

```yaml
# auditbeat.yml
output.file:
  path: /var/log/auditbeat
  filename: auditbeat.ndjson
  rotate_every_kb: 102400
  number_of_files: 7
```

```ini
# inputs.conf on the universal forwarder
[monitor:///var/log/auditbeat/auditbeat.ndjson*]
sourcetype = auditbeat
index = auditbeat
disabled = false
```

## Recommended `auditbeat.yml`

Option names below were checked against the Auditbeat v8.19.23 and v9.5.5 source.

```yaml
auditbeat.modules:

# Kernel audit framework -> Processes, Ports, Authentication, Account_Management,
# Services, Auditing_Changes, Filesystem (watches), Network_Traffic
- module: auditd
  resolve_ids: true            # user/group names (user.name, user.audit.name, ...)
  include_raw_message: false   # keeps events small (Splunk [kv] maxchars)
  include_warnings: false
  failure_mode: silent
  backlog_limit: 8192
  backpressure_strategy: auto
  audit_rules: |
    # Process execution -> Endpoint.Processes
    -a always,exit -F arch=b64 -S execve -S execveat -k exec
    -a always,exit -F arch=b32 -S execve -k exec
    # Network -> Network_Traffic (connect/accept) and Endpoint.Ports (bind)
    -a always,exit -F arch=b64 -S connect -F a2=16 -k net_connect
    -a always,exit -F arch=b64 -S connect -F a2=28 -k net_connect
    -a always,exit -F arch=b64 -S accept -S accept4 -k net_accept
    -a always,exit -F arch=b64 -S bind -k net_bind
    # Identity files -> Endpoint.Filesystem with actor
    -w /etc/passwd -p wa -k identity
    -w /etc/group -p wa -k identity
    -w /etc/shadow -p rwa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/sudoers -p wa -k sudoers
    -w /etc/sudoers.d/ -p wa -k sudoers
    # Audit configuration tampering -> Change.Auditing_Changes
    -w /etc/audit/ -p wa -k auditconfig
    -w /sbin/auditctl -p x -k audittools
  # USER_LOGIN, USER_AUTH, ADD_USER, SERVICE_START, CONFIG_CHANGE, ... are
  # user-space records and need no rules.

# File integrity -> Endpoint.Filesystem
- module: file_integrity
  paths: [/bin, /usr/bin, /sbin, /usr/sbin, /etc]
  recursive: true
  backend: ebpf              # adds the acting process and user (CIM user); "kprobes" on
                             # older kernels. "auto" means fsnotify on Linux: no actor.
  hash_types: [sha256, sha1] # default is sha1 only; CIM file_hash prefers sha256
  max_file_size: 100 MiB
  scan_at_start: true        # initial_scan baseline (kept untagged)
  exclude_files: ['(?i)\.sw[nop]$', '~$', '/\.git($|/)']

# System module
- module: system
  datasets: [host, login, package, process, socket, user]
  state.period: 12h                    # inventory snapshots (Inventory OS/Network/User)
  user.detect_password_changes: true   # password_changed -> Account_Management
  login.wtmp_file_pattern: /var/log/wtmp*
  login.btmp_file_pattern: /var/log/btmp*
  process.backend: kernel_tracing      # eBPF "quark" backend: every exec, not only polled processes
  process.hash.hash_types: [sha256]    # -> process_hash
  process.hash.max_file_size: 100 MiB

processors:
  - add_host_metadata: ~               # host.name, host.ip, host.os -> dest, dvc, os
```

### Optional: parent process name, path and command line

Auditbeat only sends `process.parent.pid`. The following processors look the parent up in `/proc` on the Auditbeat host and fill
`process.parent.name`, `process.parent.executable` and `process.parent.args`. The add-on maps them to `parent_process_name`,
`parent_process_path` and `parent_process` when they are present. This only works while the parent is still running (true for
shells and service managers, not for short-lived parents), and costs a `/proc` read per event.

```yaml
processors:
  - add_process_metadata:
      match_pids: [process.parent.pid]
      target: _parent
      include_fields: [process.name, process.executable, process.args]
      ignore_missing: true
  - rename:
      fields:
        - {from: _parent.process.name, to: process.parent.name}
        - {from: _parent.process.executable, to: process.parent.executable}
        - {from: _parent.process.args, to: process.parent.args}
      ignore_missing: true
      fail_on_error: false
  - drop_fields:
      fields: [_parent]
      ignore_missing: true
```

## Contents

```
SOC-TA-auditbeat/
  app.manifest
  README.md
  LICENSE.txt
  default/app.conf
  default/props.conf         sourcetype auditbeat: parsing, KV_MODE=json, FIELDALIAS, EVAL, LOOKUP
  default/transforms.conf    lookup definitions (no index-time transforms)
  default/eventtypes.conf    32 eventtypes, one per Auditbeat event class
  default/tags.conf          CIM constraint tags
  default/macros.conf        `auditbeat_index`, `auditbeat`
  lookups/auditbeat_actions.csv      event class -> action, status, change_type, object_category, result, signature
  lookups/auditd_message_types.csv   auditd record type -> numeric ID and description (217 types)
  metadata/default.meta      export = system
  samples/                   SYNTHETIC Auditbeat events (79)       [repository only, not packaged]
```

Helper fields added at search time: `auditbeat_dataset`, `auditbeat_action`, `auditbeat_outcome` (lookup keys),
`auditd_message_type_id`, `auditd_message_type_description`.

## Validation searches

Replace the time range as needed. Each search lists the CIM fields the dataset is expected to populate.

Endpoint has several root datasets, so name each one (`from datamodel=Endpoint` alone only searches the first, Ports):

```spl
| tstats count from datamodel=Endpoint.Processes by sourcetype, nodename
| tstats count from datamodel=Endpoint.Ports by sourcetype, nodename
| tstats count from datamodel=Endpoint.Services by sourcetype, nodename
| tstats count from datamodel=Endpoint.Filesystem by sourcetype, nodename
| tstats count from datamodel=Authentication by sourcetype, nodename
| tstats count from datamodel=Change by sourcetype, nodename
| tstats count from datamodel=Network_Traffic by sourcetype, nodename
| tstats count from datamodel=Compute_Inventory by sourcetype, nodename
```

```spl
| datamodel Endpoint Processes search | search sourcetype=auditbeat
| table _time Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.process_id Processes.parent_process_id Processes.parent_process_name Processes.process_hash Processes.action

| datamodel Endpoint Ports search | search sourcetype=auditbeat
| table _time Ports.dest Ports.dest_port Ports.transport Ports.state Ports.user Ports.process_id

| datamodel Endpoint Services search | search sourcetype=auditbeat
| table _time Services.dest Services.service Services.service_name Services.status Services.user

| datamodel Endpoint Filesystem search | search sourcetype=auditbeat
| table _time Filesystem.dest Filesystem.action Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.file_size Filesystem.file_acl Filesystem.file_create_time Filesystem.file_modify_time Filesystem.user

| datamodel Authentication Authentication search | search sourcetype=auditbeat
| table _time Authentication.action Authentication.app Authentication.src Authentication.dest Authentication.user Authentication.src_user Authentication.signature Authentication.signature_id Authentication.authentication_method

| datamodel Authentication Privileged_Authentication search | search sourcetype=auditbeat
| table _time Authentication.action Authentication.app Authentication.user Authentication.src_user Authentication.dest

| datamodel Change Account_Management search | search sourcetype=auditbeat
| table _time All_Changes.action All_Changes.status All_Changes.user All_Changes.src_user All_Changes.object All_Changes.object_category All_Changes.object_attrs All_Changes.command All_Changes.dest All_Changes.result

| datamodel Change Endpoint_Changes search | search sourcetype=auditbeat
| table _time All_Changes.action All_Changes.change_type All_Changes.object All_Changes.object_category All_Changes.object_attrs All_Changes.dest

| datamodel Change Auditing_Changes search | search sourcetype=auditbeat
| table _time All_Changes.action All_Changes.object All_Changes.object_attrs All_Changes.user All_Changes.command

| datamodel Network_Traffic All_Traffic search | search sourcetype=auditbeat
| table _time All_Traffic.action All_Traffic.src All_Traffic.src_port All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.protocol All_Traffic.direction All_Traffic.bytes_in All_Traffic.bytes_out All_Traffic.app All_Traffic.user All_Traffic.process_id

| datamodel Compute_Inventory All_Inventory search | search sourcetype=auditbeat
| table _time All_Inventory.dest All_Inventory.os All_Inventory.version All_Inventory.family All_Inventory.ip All_Inventory.mac All_Inventory.user All_Inventory.shell All_Inventory.interactive All_Inventory.tag
```

Event-class check (every Auditbeat class, its eventtypes and tags):

```spl
`auditbeat` | stats count by event.module auditbeat_dataset auditbeat_action eventtype tag
```

## Validation status (1.0.0)

Validated on **Splunk Enterprise 10.6.1** (`splunk/splunk` Docker image) with **Splunk_SA_CIM 6.1.0**, using the 79 synthetic
sample events. The full per-field report is generated by `auditbeat/tools/validate_splunk.py`.

* `splunk btool check --app=SOC-TA-auditbeat`: no errors.
* Parsing: 79/79 events, one event per line, `_time` equal to `@timestamp` to the millisecond, no duplicated JSON fields.
* `splunk-appinspect inspect --mode precert` on the package: 0 errors, 0 failures, 0 warnings.

| Dataset | Sample events | Populated CIM fields | Empty (data not available in Auditbeat) |
|---|---|---|---|
| Endpoint.Processes | 8 | action, dest, user, user_id, process, process_name, process_exec, process_path, process_id, process_guid, process_hash, process_current_directory, process_integrity_level, parent_process_id, os, vendor_product; parent_process* only with the processor recipe | original_file_name, loaded_file, parent_process_guid/hash, cpu_load_percent, mem_used |
| Endpoint.Ports | 2 | dest, dest_port, state, user, process_id, creation_time, vendor_product | transport, src (src_port is the DM default `0`) |
| Endpoint.Services | 3 | dest, service, service_name, service_id, status, user, process_id, vendor_product | service_path, start_mode, description, service_exec/hash/dll* |
| Endpoint.Filesystem | 13 | action, dest, file_path, file_name, file_hash, file_size, file_acl, file_modify_time, file_create_time, user, process_id, process_guid, image, vendor_product | file_access_time |
| Authentication (+ Failed, Privileged) | 4 (2, 2) | action, app, src, dest, user, user_id, src_user, signature, signature_id, session_id, process, authentication_method | reason, duration, user_agent, *_nt_domain |
| Change.Account_Management (Created 3, Deleted 3, Updated 5, Lockouts 1) | 12 | action, status, change_type, object, object_id, object_attrs, object_category, command, user, user_name, src_user, src_user_name, src, dest, dvc, result | object_path, *_nt_domain |
| Change.Endpoint_Changes (Restarts 1) | 5 | action, status, change_type, object, object_id, object_attrs, object_category, src, dest, dvc, result | user, command, object_path |
| Change.Auditing_Changes | 1 | action, status, change_type, object, object_attrs, object_category, command, user, src, dest, dvc | object_id, object_path |
| Network_Traffic (Allowed 8, Blocked 1) | 9 | action, src, src_ip, src_port, dest, dest_ip, dest_port, transport, protocol, protocol_version, direction, bytes, bytes_in, bytes_out, packets*, duration, app, user, process_id, flow_id, dvc, dvc_ip | MAC, NAT, zone, rule, TCP flag, ICMP fields |
| Compute_Inventory OS / Network / User (Default_Accounts 1) | 1 / 1 / 3 | os, version, family, description; ip, mac, name; user, user_id, shell, interactive | dns, interface, password, serial |

## Development

The repository folder `auditbeat/tools/` (not part of the package):

* `generate_samples.py` regenerates `samples/` (synthetic events).
* `generate_lookups.py` regenerates both lookups (`auditbeat_actions.csv` from its embedded table).
* `validate_splunk.py --load` indexes the samples into a running Splunk and writes the field-population report.

From the repository root, `python3 tools/check_conf.py auditbeat/SOC-TA-auditbeat` runs the static conf check (a
btool-style pass over the `.conf` files and lookup references) and `sh tools/build_package.sh auditbeat` builds the
package (without `samples/`).
