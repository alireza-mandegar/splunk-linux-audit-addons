#!/usr/bin/env python3
"""Static checks for a Splunk add-on's .conf files (a btool-style syntax pass).

Checks:
  * every line is a comment, blank, [stanza] or key = value
  * no duplicate stanzas and no duplicate keys inside a stanza
  * a continuation backslash is the last character of its line
  * tags.conf only references eventtypes that exist; every eventtype search
    starts with sourcetype= and contains no pipe
  * every REPORT- / TRANSFORMS- in props.conf names transforms.conf stanzas
    that exist and have a REGEX
  * every LOOKUP- in props.conf names a transforms.conf stanza whose CSV
    exists and contains the referenced input/output columns
  * EVAL- expressions have balanced parentheses and quotes
  * app.conf and app.manifest carry the same version

Usage: python3 tools/check_conf.py <app directory>
       e.g. python3 tools/check_conf.py auditd/SOC-TA-auditd
"""

import csv
import os
import re
import sys

if len(sys.argv) != 2:
    sys.exit(__doc__)
APP = sys.argv[1]
errors = []


def err(msg):
    errors.append(msg)


def parse(path):
    stanzas = {}
    order = []
    current = "default"
    stanzas[current] = {}
    lines = open(path, encoding="utf-8").read().split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i]
        lineno = i + 1
        i += 1
        if re.search(r"\\[ \t]+$", raw):
            err("%s:%d: whitespace after continuation backslash" % (path, lineno))
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^\[(.*)\]\s*$", raw)
        if m:
            current = m.group(1)
            if current in stanzas and current != "default":
                err("%s:%d: duplicate stanza [%s]" % (path, lineno, current))
            stanzas.setdefault(current, {})
            order.append(current)
            continue
        value_lines = [raw]
        while value_lines[-1].endswith("\\") and i < len(lines):
            value_lines.append(lines[i])
            i += 1
        line = "\n".join(value_lines)
        m = re.match(r"^([^=\s][^=]*?)\s*=\s?(.*)$", line, re.S)
        if not m:
            err("%s:%d: not a key = value line: %r" % (path, lineno, raw[:80]))
            continue
        key, value = m.group(1), m.group(2)
        if key in stanzas[current]:
            err("%s:%d: duplicate key %r in [%s]" % (path, lineno, key, current))
        stanzas[current][key] = (value, lineno)
    return stanzas


def balanced(expr):
    depth = 0
    quote = None
    prev = ""
    for ch in expr:
        if quote:
            if ch == quote and prev != "\\":
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
        prev = ch
    return depth == 0 and quote is None


def main():
    default = os.path.join(APP, "default")
    confs = {f: parse(os.path.join(default, f)) for f in sorted(os.listdir(default)) if f.endswith(".conf")}
    for f in confs:
        print("parsed %-18s %3d stanzas" % (f, len([s for s in confs[f] if s != "default"])))

    eventtypes = confs.get("eventtypes.conf", {})
    for name, kv in eventtypes.items():
        if name == "default":
            continue
        search = kv.get("search", ("", 0))[0]
        if not search.startswith("sourcetype="):
            err("eventtypes.conf [%s]: search does not start with sourcetype=" % name)
        if "|" in search or "`" in search:
            err("eventtypes.conf [%s]: pipes and macros are not allowed in eventtypes" % name)

    for stanza, kv in confs.get("tags.conf", {}).items():
        if stanza == "default":
            continue
        m = re.match(r"eventtype=(.+)", stanza)
        if not m or m.group(1) not in eventtypes:
            err("tags.conf [%s]: no such eventtype" % stanza)
        for tag, (val, line) in kv.items():
            if val not in ("enabled", "disabled"):
                err("tags.conf:%d: tag %s has value %r" % (line, tag, val))

    transforms = confs.get("transforms.conf", {})
    for stanza, kv in confs.get("props.conf", {}).items():
        for key, (val, line) in kv.items():
            if key.startswith("EVAL-") and not balanced(val):
                err("props.conf:%d: %s has unbalanced parentheses or quotes" % (line, key))
            if key.startswith("REPORT-") or key.startswith("TRANSFORMS-"):
                for tname in [t.strip() for t in val.split(",") if t.strip()]:
                    if tname not in transforms:
                        err("props.conf:%d: %s references unknown transform %s" % (line, key, tname))
                    elif "REGEX" not in transforms[tname]:
                        err("transforms.conf [%s]: no REGEX" % tname)
            if key.startswith("LOOKUP-"):
                toks = re.findall(r'"[^"]*"|\S+', val)
                tname = toks[0]
                if tname not in transforms:
                    err("props.conf:%d: %s references unknown transform %s" % (line, key, tname))
                    continue
                csv_path = os.path.join(APP, "lookups", transforms[tname]["filename"][0])
                if not os.path.exists(csv_path):
                    err("transforms.conf [%s]: missing %s" % (tname, csv_path))
                    continue
                header = next(csv.reader(open(csv_path, encoding="utf-8")))
                fields, mode = [], "in"
                j = 1
                while j < len(toks):
                    t = toks[j]
                    if t in ("OUTPUT", "OUTPUTNEW"):
                        j += 1
                        continue
                    fields.append(t)
                    j += 3 if j + 1 < len(toks) and toks[j + 1] == "AS" else 1
                for fld in fields:
                    if fld not in header:
                        err("props.conf:%d: %s column %r not in %s" % (line, key, fld, os.path.basename(csv_path)))
                mt = transforms[tname].get("match_type", ("", 0))[0]
                for col in re.findall(r"WILDCARD\((\w+)\)", mt):
                    if col not in header:
                        err("transforms.conf [%s]: WILDCARD column %s not in CSV" % (tname, col))

    app = confs.get("app.conf", {})
    versions = {app.get(st, {}).get("version", ("", 0))[0] for st in ("launcher", "id")}
    manifest = os.path.join(APP, "app.manifest")
    if os.path.exists(manifest):
        import json
        versions.add(json.load(open(manifest, encoding="utf-8"))["info"]["id"]["version"])
    if len(versions) != 1:
        err("app.conf [launcher]/[id] and app.manifest disagree on the version: %s" % sorted(versions))

    for f in os.listdir(os.path.join(APP, "lookups")):
        rows = list(csv.reader(open(os.path.join(APP, "lookups", f), encoding="utf-8")))
        widths = {len(r) for r in rows}
        if len(widths) != 1:
            err("lookups/%s: inconsistent column counts %s" % (f, widths))

    if errors:
        print("\n".join("ERROR " + e for e in errors))
        sys.exit(1)
    print("OK: %s has no syntax or reference errors" % os.path.basename(os.path.normpath(APP)))


if __name__ == "__main__":
    main()
