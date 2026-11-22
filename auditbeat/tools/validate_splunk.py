#!/usr/bin/env python3
"""Validate SOC-TA-auditbeat against a running Splunk instance (e.g. splunk/splunk in Docker).

Steps:
  1. create the index and oneshot-index every file in SOC-TA-auditbeat/samples/
  2. parsing checks: one event per line, _time == @timestamp, no duplicated JSON fields
  3. event classes: auditbeat_action -> eventtype -> tag
  4. for every CIM dataset: | datamodel <model> <dataset> search, then count which CIM
     fields are populated (not null, not "unknown") using the field lists from the
     installed Splunk_SA_CIM data model JSON
  5. | tstats count from datamodel=<model> by sourcetype, nodename

Writes a Markdown report.

Usage:
  python3 auditbeat/tools/validate_splunk.py --url https://127.0.0.1:8089 --password-file PW \
      --models-dir Splunk_SA_CIM/default/data/models --report report.md [--load]
"""

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SAMPLES_IN_CONTAINER = "/opt/splunk/etc/apps/SOC-TA-auditbeat/samples"
SAMPLES_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SOC-TA-auditbeat", "samples")
INDEX = "auditbeat"
ST = "auditbeat"

# (model, dataset, CIM objects whose fields apply to the dataset)
DATASETS = [
    ("Endpoint", "Processes", ["Processes"]),
    ("Endpoint", "Ports", ["Ports"]),
    ("Endpoint", "Services", ["Services"]),
    ("Endpoint", "Filesystem", ["Filesystem"]),
    ("Authentication", "Authentication", ["Authentication"]),
    ("Authentication", "Failed_Authentication", ["Authentication"]),
    ("Authentication", "Privileged_Authentication", ["Authentication"]),
    ("Change", "Account_Management", ["All_Changes", "Account_Management"]),
    ("Change", "Accounts_Created", ["All_Changes", "Account_Management"]),
    ("Change", "Accounts_Deleted", ["All_Changes", "Account_Management"]),
    ("Change", "Accounts_Updated", ["All_Changes", "Account_Management"]),
    ("Change", "Account_Lockouts", ["All_Changes", "Account_Management"]),
    ("Change", "Endpoint_Changes", ["All_Changes"]),
    ("Change", "Endpoint_Restarts", ["All_Changes"]),
    ("Change", "Auditing_Changes", ["All_Changes"]),
    ("Network_Traffic", "All_Traffic", ["All_Traffic"]),
    ("Network_Traffic", "Allowed_Traffic", ["All_Traffic"]),
    ("Network_Traffic", "Blocked_Traffic", ["All_Traffic"]),
    ("Compute_Inventory", "OS", ["All_Inventory", "OS"]),
    ("Compute_Inventory", "Network", ["All_Inventory", "Network"]),
    ("Compute_Inventory", "User", ["All_Inventory", "User"]),
    ("Compute_Inventory", "Default_Accounts", ["All_Inventory", "User"]),
]


class Splunk:
    def __init__(self, url, password):
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(("admin:" + password).encode()).decode()
        # Local test container with a self-signed certificate.
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, path, data=None, method=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.url + path, data=body, headers={"Authorization": self.auth}, method=method)
        with urllib.request.urlopen(req, context=self.ctx, timeout=600) as resp:
            return resp.read().decode()

    def search(self, spl, earliest="0"):
        if not spl.lstrip().startswith("|"):
            spl = "search " + spl
        out = self.request("/services/search/jobs/export", {
            "search": spl, "output_mode": "json", "earliest_time": earliest, "latest_time": "now"})
        rows = []
        for line in out.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("result") is not None:
                rows.append(obj["result"])
            for m in obj.get("messages", []) or []:
                if m.get("type") in ("ERROR", "FATAL"):
                    raise RuntimeError("%s: %s" % (spl, m.get("text")))
        return rows


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def cim_fields(models_dir, model, objects):
    """field -> (recommended flag, output prefix).

    '| datamodel' prefixes each field with the lineage of the object that defines it,
    e.g. All_Changes.Account_Management.src_user.
    """
    m = json.load(open(os.path.join(models_dir, model + ".json")))
    parents = {o["objectName"]: o.get("parentName") for o in m["objects"]}

    def lineage(name):
        path = [name]
        while parents.get(path[0]) in parents:
            path.insert(0, parents[path[0]])
        return ".".join(path)

    fields = {}
    for o in m["objects"]:
        if o["objectName"] not in objects:
            continue
        defs = list(o.get("fields", []))
        for c in o.get("calculations", []):
            defs.extend(c.get("outputFields", []))
        for f in defs:
            cmt = f.get("comment") or {}
            if isinstance(cmt, str):
                cmt = {}
            if cmt.get("ta_relevant") is False or f["fieldName"] in ("tag", "_time", "host", "source", "sourcetype"):
                continue
            fields[f["fieldName"]] = ("rec" if cmt.get("recommended") else "", lineage(o["objectName"]))
    return fields


def load(sp):
    # Start from an empty index: drop it if it exists ("| delete" needs the can_delete role).
    try:
        sp.request("/services/data/indexes/" + INDEX, method="DELETE")
        print("removed existing index", INDEX)
        for _ in range(60):
            try:
                sp.request("/services/data/indexes/" + INDEX)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    break
            time.sleep(2)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    sp.request("/services/data/indexes", {"name": INDEX})
    print("created index", INDEX)
    files = sorted(f for f in os.listdir(SAMPLES_LOCAL) if f.endswith(".ndjson"))
    expected = sum(sum(1 for _ in open(os.path.join(SAMPLES_LOCAL, f))) for f in files)
    for f in files:
        sp.request("/services/data/inputs/oneshot", {
            "name": SAMPLES_IN_CONTAINER + "/" + f, "sourcetype": ST, "index": INDEX})
    for _ in range(60):
        n = int(sp.search("| tstats count where index=%s sourcetype=%s" % (INDEX, ST))[0]["count"])
        if n >= expected:
            break
        time.sleep(5)
    print("indexed %d / %d sample events" % (n, expected))
    return expected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--models-dir", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--load", action="store_true")
    a = ap.parse_args()
    sp = Splunk(a.url, open(a.password_file).read().strip())
    if a.load:
        load(sp)

    rep = ["# Live validation report", "",
           "Splunk %s, Splunk_SA_CIM 6.1.0, index `%s`, sourcetype `%s`, synthetic samples." % (
               sp.search("| rest /services/server/info splunk_server=local | fields version")[0]["version"], INDEX, ST), ""]

    # --- parsing
    base = "index=%s sourcetype=%s" % (INDEX, ST)
    p = sp.search(base + " | eval ts=strptime('@timestamp', \"%Y-%m-%dT%H:%M:%S.%3N%Z\")"
                  " | eval time_ok=if(abs(_time-ts)<0.001,1,0), lines=linecount, dup=if(mvcount('event.module')>1,1,0)"
                  " | stats count sum(time_ok) as time_ok max(lines) as max_lines sum(dup) as dup_fields")[0]
    rep += ["## Parsing", "",
            "| Check | Result |", "|---|---|",
            "| events indexed | %s |" % p["count"],
            "| `_time` equals `@timestamp` (ms) | %s / %s |" % (p["time_ok"], p["count"]),
            "| max linecount (1 = one event per line) | %s |" % p["max_lines"],
            "| events with duplicated JSON fields (KV_MODE + indexed) | %s |" % p["dup_fields"], ""]

    # --- event classes
    rows = sp.search(base + " | eval et=mvjoin(mvsort(eventtype),\" \"), tg=mvjoin(mvsort(tag),\" \")"
                     " | fillnull value=\"\" action et tg"
                     " | stats count by event.module auditbeat_dataset auditbeat_action auditbeat_outcome action et tg"
                     " | sort event.module auditbeat_dataset auditbeat_action")
    rep += ["## Event classes → eventtypes → tags", "",
            "| module | dataset | auditbeat_action | outcome | CIM action | eventtype(s) | tags | n |",
            "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        rep.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r.get("event.module"), r.get("auditbeat_dataset"), r.get("auditbeat_action"), r.get("auditbeat_outcome"),
            r.get("action", ""), r.get("et", "") or "–", r.get("tg", "") or "–", r.get("count")))
    rep.append("")

    # --- tstats per model
    rep += ["## `| tstats count from datamodel=<DM> by sourcetype, nodename`", "",
            "| Data model | nodename | count |", "|---|---|---|"]
    # Endpoint has several root datasets; "from datamodel=Endpoint" would only search the first one.
    for model in ("Endpoint.Processes", "Endpoint.Ports", "Endpoint.Services", "Endpoint.Filesystem",
                  "Authentication", "Change", "Network_Traffic", "Compute_Inventory"):
        for r in sp.search("| tstats count from datamodel=%s where sourcetype=%s by sourcetype, nodename" % (model, ST)):
            rep.append("| %s | %s | %s |" % (model, r["nodename"], r["count"]))
    rep.append("")

    # --- field population per dataset
    rep += ["## Field population per CIM dataset", "",
            "`populated` = not null and not `unknown` (the data model's default). Fields marked *rec* are recommended in the CIM JSON.", ""]
    summary = []
    for model, ds, objects in DATASETS:
        fields = cim_fields(a.models_dir, model, objects)
        events = sp.search("| datamodel %s %s search | search sourcetype=%s" % (model, ds, ST))
        n = len(events)
        summary.append((model, ds, n))
        rep += ["### %s.%s: %d events" % (model, ds, n), ""]
        if not n:
            rep += ["_no events_", ""]
            continue
        rep += ["| CIM field | | populated | example values |", "|---|---|---|---|"]
        empty = []
        for fld in sorted(fields):
            rec, owner = fields[fld]
            vals = []
            cnt = 0
            for e in events:
                v = [x for x in as_list(e.get(owner + "." + fld)) if x not in ("", "unknown")]
                if v:
                    cnt += 1
                    vals.extend(v)
            if cnt:
                ex = ", ".join("`%s`" % x for x in list(dict.fromkeys(vals))[:4])
                rep.append("| %s | %s | %d/%d | %s |" % (fld, rec, cnt, n, ex.replace("|", "\\|")))
            else:
                empty.append(fld + (" (rec)" if rec else ""))
        rep += ["", "Empty: " + (", ".join(empty) if empty else "none"), ""]

    rep[4:4] = ["## Summary", "", "| Dataset | events |", "|---|---|"] + \
        ["| %s.%s | %d |" % s for s in summary] + [""]
    open(a.report, "w").write("\n".join(rep) + "\n")
    print("report written:", a.report)
    for s in summary:
        print("%-18s %-26s %3d" % s)


if __name__ == "__main__":
    main()
