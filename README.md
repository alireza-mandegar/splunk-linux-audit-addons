# Splunk CIM add-ons for Linux auditing: auditd and Auditbeat

Two Splunk add-ons that map Linux audit data to the **Splunk Common Information Model (CIM)**, so Enterprise Security
correlation searches, ESCU detections and CIM dashboards work on Linux hosts.

| Add-on | Data it understands | Sourcetype | Folder |
|---|---|---|---|
| **SOC-TA-auditd** | The Linux audit daemon log, `/var/log/audit/audit.log` (`log_format = ENRICHED`) | `auditd` | [`auditd/`](auditd/SOC-TA-auditd/README.md) |
| **SOC-TA-auditbeat** | Elastic Auditbeat 8.19 / 9.x events (ECS JSON): `auditd`, `file_integrity` and `system` modules | `auditbeat` | [`auditbeat/`](auditbeat/SOC-TA-auditbeat/README.md) |

Both add-ons work at search time only (field aliases, calculated fields, lookups, eventtypes, tags). They never
overwrite existing fields: CIM fields are added beside the original ones.

**Which one do I need?** Install the one that matches how the data reaches Splunk. If a universal forwarder reads
`audit.log`, use **SOC-TA-auditd**. If you run Auditbeat, use **SOC-TA-auditbeat**. Both can run side by side; just don't
send the same hosts' audit events through both paths.

## CIM coverage

| CIM data model | SOC-TA-auditd | SOC-TA-auditbeat |
|---|---|---|
| Endpoint.Processes | execve, sudo commands | auditd execve, sudo commands, system/process |
| Endpoint.Ports | bind | auditd bind |
| Endpoint.Services | systemd service start/stop | systemd service start/stop |
| Endpoint.Filesystem | audit watches (`-w`, `-F path=`) | audit watches, file_integrity |
| Authentication (+ Privileged) | logons, sudo / su | logons, sudo / su, wtmp (optional) |
| Change.Account_Management | users, groups, passwords, lockouts | users, groups, passwords, lockouts, system/user |
| Change.Endpoint_Changes | rpm/dnf packages, boot, shutdown | packages, reboots, host changes |
| Change.Auditing_Changes | audit rules and daemon changes | audit rules and daemon changes |
| Network_Traffic | connect, accept | auditd connect/accept, system/socket flows |
| Inventory | – | hosts, users |

Each add-on's README lists the exact record types, field mappings, known gaps and validation results.

## Download

Get the packages from the [**Releases**](../../releases/latest) page:

* `SOC-TA-auditd-<version>.tgz`
* `SOC-TA-auditbeat-<version>.tgz`

Install with **Apps → Manage Apps → Install app from file**, or `splunk install app <package>.tgz`. The
[Splunk Common Information Model add-on](https://splunkbase.splunk.com/app/1621) must be installed on the search heads.

| Splunk tier | Install the add-on? |
|---|---|
| Search heads (incl. ES, SHC via the deployer) | **Yes**: all search-time knowledge |
| Indexers / heavy forwarders | **Yes**: event breaking and timestamps |
| Universal forwarders | Recommended: `EVENT_BREAKER` for clean load balancing |
| Splunk Cloud | Install on the search head stack |

## Quick start: auditd

1. In `/etc/audit/auditd.conf` set `log_format = ENRICHED` (the default since audit 3.0) and restart auditd.
2. Load audit rules (a recommended set is in the [auditd add-on README](auditd/SOC-TA-auditd/README.md#recommended-audit-rules)).
3. Give the forwarder read access to `/var/log/audit/` and add to `inputs.conf`:

   ```ini
   [monitor:///var/log/audit/audit.log]
   sourcetype = auditd
   index = auditd
   ```

## Quick start: Auditbeat

1. Write Auditbeat's events to a file (a recommended `auditbeat.yml` is in the
   [Auditbeat add-on README](auditbeat/SOC-TA-auditbeat/README.md#recommended-auditbeatyml)):

   ```yaml
   output.file:
     path: /var/log/auditbeat
     filename: auditbeat.ndjson
   ```

2. Monitor it with the universal forwarder:

   ```ini
   [monitor:///var/log/auditbeat/auditbeat.ndjson*]
   sourcetype = auditbeat
   index = auditbeat
   ```

## After installing

* Point the `auditd_index` / `auditbeat_index` macro at your index if it is not `auditd` / `auditbeat`.
* Add the index to the CIM index allowlists (CIM Setup page, or the `cim_<Model>_indexes` macros) and rebuild the data
  model accelerations.
* Check the data models:

  ```spl
  | tstats count from datamodel=Endpoint.Processes by sourcetype, nodename
  | tstats count from datamodel=Authentication by sourcetype, nodename
  | tstats count from datamodel=Change by sourcetype, nodename
  ```

## Validation

Both add-ons are tested on Splunk Enterprise 10.6.1 with the Splunk CIM add-on, using the synthetic samples in each
`samples/` folder: config check with `btool`, event parsing, eventtypes and tags, and the population of every CIM field
per data model. The results are in each add-on's README. Every push also runs a static check, the package build and
Splunk AppInspect (`precert` mode) in GitHub Actions.

## Repository layout

```
auditd/
  SOC-TA-auditd/        the add-on (packaged)
    samples/            synthetic audit.log records (not packaged)
  tools/                sample and lookup generators, live validation against Splunk
auditbeat/
  SOC-TA-auditbeat/     the add-on (packaged)
    samples/            synthetic Auditbeat events (not packaged)
  tools/                sample and lookup generators, live validation against Splunk
tools/
  build_package.sh      builds dist/SOC-TA-<name>-<version>.tgz
  check_conf.py         static .conf check (syntax, references, versions)
```

## Build from source

```bash
sh tools/build_package.sh            # both add-ons
sh tools/build_package.sh auditd     # one add-on
```

The packages land in `dist/` and contain only `app.manifest`, `README.md`, `LICENSE.txt`, `default/`, `lookups/` and
`metadata/`.

Releases are built by GitHub Actions: pushing a tag `v<version>` (for example `v1.0.0`) builds both packages, runs
AppInspect and attaches the packages to a GitHub release.

## Contributing

Issues and pull requests are welcome. Please run `python3 tools/check_conf.py <add-on folder>` before sending a change,
and add a synthetic sample (never real logs) for any new event class.

## License

[MIT](LICENSE)
