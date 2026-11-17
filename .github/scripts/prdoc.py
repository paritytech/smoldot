#!/usr/bin/env python3
# Smoldot
# Copyright (C) 2026  Parity Technologies (UK) Ltd.
# SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Validate prdoc files and turn them into a `wasm-node/CHANGELOG.md` section.

    prdoc.py check [FILE...]
    prdoc.py release VERSION [--date YYYY-MM-DD]
"""

import argparse
import datetime
import pathlib
import re
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
PRDOC_DIR = ROOT / "prdoc"
CHANGELOG = ROOT / "wasm-node" / "CHANGELOG.md"
REPO_URL = "https://github.com/paritytech/smoldot"
SECTIONS = ["added", "changed", "fixed", "removed"]
FILE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*\.prdoc$")
PR_FILE_NAME = re.compile(r"^pr_(\d+)\.prdoc$")
PR_SUBJECT = re.compile(r"\(#(\d+)\)\s*$|^Merge pull request #(\d+)")


class PrdocError(Exception):
    pass


def _issue_list(doc, key):
    value = doc.get(key, [])
    if not isinstance(value, list) or not all(
        isinstance(n, int) and not isinstance(n, bool) and n > 0 for n in value
    ):
        raise PrdocError(f"`{key}` must be a list of issue numbers")
    return value


def load(path):
    path = pathlib.Path(path)
    if not FILE_NAME.match(path.name):
        raise PrdocError("file name must match `[a-z0-9][a-z0-9._-]*.prdoc`")

    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise PrdocError(f"invalid YAML: {e}")
    if not isinstance(doc, dict):
        raise PrdocError("top level must be a mapping")

    unknown = set(doc) - {"changes", "fixes", "related"}
    if unknown:
        raise PrdocError(f"unknown fields: {', '.join(sorted(unknown))}")

    changes = doc.get("changes")
    if not isinstance(changes, list) or not changes:
        raise PrdocError("`changes` must be a non-empty list")
    for i, change in enumerate(changes):
        if not isinstance(change, dict) or set(change) != {"section", "description"}:
            raise PrdocError(f"changes[{i}] must have exactly `section` and `description`")
        if change["section"] not in SECTIONS:
            raise PrdocError(f"changes[{i}].section must be one of: {', '.join(SECTIONS)}")
        if not isinstance(change["description"], str) or not change["description"].strip():
            raise PrdocError(f"changes[{i}].description must be a non-empty string")

    return {
        "path": path,
        "changes": changes,
        "fixes": _issue_list(doc, "fixes"),
        "related": _issue_list(doc, "related"),
    }


def bullet(prdoc, change):
    text = " ".join(change["description"].split())
    refs = f"[#{prdoc['pr']}]({REPO_URL}/pull/{prdoc['pr']})"
    for key, label in (("fixes", "fixes"), ("related", "related to")):
        if prdoc[key]:
            issues = ", ".join(f"[#{n}]({REPO_URL}/issues/{n})" for n in prdoc[key])
            refs += f"; {label} {issues}"
    return f"- {text} ({refs})"


def pending_files():
    return sorted(f for f in PRDOC_DIR.glob("*.prdoc") if not f.name.startswith("."))


def pr_number(path):
    m = PR_FILE_NAME.match(path.name)
    if m:
        return int(m.group(1))
    subject = subprocess.run(
        ["git", "log", "-1", "--diff-filter=A", "--format=%s", "--", str(path.relative_to(ROOT))],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()
    m = PR_SUBJECT.search(subject)
    if not m:
        raise PrdocError(
            f"no PR number found in the subject of the commit that added it ({subject or 'no commit, or a shallow clone'!r}),"
            " rename it to `pr_<PR number>.prdoc`"
        )
    return int(m.group(1) or m.group(2))


def cmd_check(files):
    files = files or pending_files()
    failed = False
    for f in files:
        try:
            load(f)
            print(f"ok: {f}")
        except (PrdocError, OSError) as e:
            print(f"error: {f}: {e}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


def cmd_release(version, date):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"error: bad version `{version}`", file=sys.stderr)
        return 1
    files = pending_files()
    if not files:
        print("error: no prdoc files in prdoc/", file=sys.stderr)
        return 1
    prdocs = []
    for f in files:
        try:
            prdoc = load(f)
            prdoc["pr"] = pr_number(f)
        except PrdocError as e:
            print(f"error: {f.relative_to(ROOT)}: {e}", file=sys.stderr)
            return 1
        prdocs.append(prdoc)
    prdocs.sort(key=lambda p: (p["pr"], p["path"].name))

    lines = [f"## {version} - {date}"]
    for section in SECTIONS:
        entries = [bullet(p, c) for p in prdocs for c in p["changes"] if c["section"] == section]
        if entries:
            lines += ["", f"### {section.capitalize()}", ""] + entries
    new_section = "\n".join(lines) + "\n"

    changelog = CHANGELOG.read_text()
    marker = "## Unreleased\n"
    if changelog.count(marker) != 1:
        print(f"error: expected exactly one `{marker.strip()}` in {CHANGELOG}", file=sys.stderr)
        return 1
    head, rest = changelog.split(marker, 1)
    rest = rest.lstrip("\n")
    if not rest.startswith("## "):
        print(f"error: `{marker.strip()}` is not empty, move its entries to prdoc files", file=sys.stderr)
        return 1
    CHANGELOG.write_text(f"{head}{marker}\n{new_section}\n{rest}")

    for f in files:
        f.unlink()

    print(new_section)
    print(f"deleted {len(files)} prdoc file(s)")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="validate prdoc files (default: all pending ones)")
    check.add_argument("files", nargs="*")
    release = sub.add_parser("release", help="write the CHANGELOG section and delete the files")
    release.add_argument("version")
    release.add_argument("--date", default=datetime.date.today().isoformat())
    args = parser.parse_args()

    if args.cmd == "check":
        return cmd_check(args.files)
    return cmd_release(args.version, args.date)


if __name__ == "__main__":
    sys.exit(main())
