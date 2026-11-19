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
# Starts with a lowercase letter or digit, then lowercase letters, digits, `.`, `_` or `-`.
FILE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*\.prdoc$")
# `pr_1234.prdoc`, group 1 is the PR number.
PR_FILE_NAME = re.compile(r"^pr_(\d+)\.prdoc$")
# Squash merge subject ending in `(#1234)`, or merge commit `Merge pull request #1234 ...`.
PR_SUBJECT = re.compile(r"\(#(\d+)\)\s*$|^Merge pull request #(\d+)")
# A blank line, or a line starting a `-`, `*`, `+` or `1.` / `1)` list item.
MULTI_PARAGRAPH = re.compile(r"\n[ \t]*\n|^[ \t]*(?:[-*+]|\d+[.)])[ \t]", re.M)
MAX_SIZE = 64 * 1024


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
        # Files come from PRs. Limit the size, and catch the RecursionError that PyYAML
        # raises on deep nesting (about 500 levels of `[`).
        if path.stat().st_size > MAX_SIZE:
            raise PrdocError("larger than 64 KiB")
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raise PrdocError("not valid UTF-8")
    except OSError as e:
        raise PrdocError(e.strerror or str(e))
    except yaml.YAMLError as e:
        raise PrdocError(f"invalid YAML: {e}")
    except RecursionError:
        raise PrdocError("invalid YAML: nested too deeply")
    if not isinstance(doc, dict):
        raise PrdocError("top level must be a mapping")

    # Keys can be any YAML scalar, such as `1:`, so convert them to text before sorting.
    unknown = set(doc) - {"changes", "fixes", "related"}
    if unknown:
        raise PrdocError(f"unknown fields: {', '.join(sorted(map(str, unknown)))}")

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
        if MULTI_PARAGRAPH.search(change["description"].strip()):
            raise PrdocError(
                f"changes[{i}].description must be one paragraph without lists, it becomes one CHANGELOG line"
            )

    return {
        "path": path,
        "changes": changes,
        "fixes": _issue_list(doc, "fixes"),
        "related": _issue_list(doc, "related"),
    }


def bullet(prdoc, change):
    # Join the wrapped lines of a `|` block into one CHANGELOG line.
    text = " ".join(change["description"].split())
    refs = f"[#{prdoc['pr']}]({REPO_URL}/pull/{prdoc['pr']})"
    for key, label in (("fixes", "fixes"), ("related", "related to")):
        if prdoc[key]:
            issues = ", ".join(f"[#{n}]({REPO_URL}/issues/{n})" for n in prdoc[key])
            refs += f"; {label} {issues}"
    return f"- {text} ({refs})"


def pending_files():
    return sorted(f for f in PRDOC_DIR.glob("*.prdoc") if not f.name.startswith("."))


def git(*args):
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as e:
        raise PrdocError(f"`git {' '.join(args)}` failed: {getattr(e, 'stderr', '') or e}".strip())


def pr_number(path):
    m = PR_FILE_NAME.match(path.name)
    if m:
        return int(m.group(1))
    if git("rev-parse", "--is-shallow-repository") == "true":
        raise PrdocError("the clone is shallow, so the commit that added it can't be found; run `git fetch --unshallow`")
    # The commit on main that added the file: a squash merge `... (#N)` or a merge commit.
    subject = git(
        "log", "-1", "--first-parent", "--diff-filter=A",
        "--format=%s", "--", str(path.relative_to(ROOT)),
    )
    if not subject:
        raise PrdocError("no commit adds it; commit it, or rename it to `pr_<PR number>.prdoc`")
    m = PR_SUBJECT.search(subject)
    if not m:
        raise PrdocError(
            f"no PR number in the subject of the commit that added it ({subject!r}), rename it to `pr_<PR number>.prdoc`"
        )
    return int(m.group(1) or m.group(2))


def cmd_check(files):
    files = files or pending_files()
    failed = False
    for f in files:
        try:
            load(f)
            print(f"ok: {f}")
        except PrdocError as e:
            print(f"error: {f}: {e}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


def cmd_release(version, date):
    # `X.Y.Z` with numbers only, no `v` prefix or suffix.
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"error: bad version `{version}`", file=sys.stderr)
        return 1
    files = pending_files()
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
    if not prdocs:
        lines += ["", "No user-visible changes."]
    new_section = "\n".join(lines) + "\n"

    changelog = CHANGELOG.read_text(encoding="utf-8")
    # Running release twice would add the same version again, since the prdoc files are gone.
    if f"\n## {version} " in changelog:
        print(f"error: {CHANGELOG} already has a `## {version}` section", file=sys.stderr)
        return 1
    marker = "## Unreleased\n"
    if changelog.count(marker) != 1:
        print(f"error: expected exactly one `{marker.strip()}` in {CHANGELOG}", file=sys.stderr)
        return 1
    head, rest = changelog.split(marker, 1)
    rest = rest.lstrip("\n")
    if not rest.startswith("## "):
        print(f"error: `{marker.strip()}` is not empty, move its entries to prdoc files", file=sys.stderr)
        return 1
    CHANGELOG.write_text(f"{head}{marker}\n{new_section}\n{rest}", encoding="utf-8")

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
