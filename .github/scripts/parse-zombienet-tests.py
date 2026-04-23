#!/usr/bin/env python3

"""
Zombienet Test Matrix Parser

Parses a YAML test-definition file into a JSON matrix for GitHub Actions.
Supports filtering out known-flaky tests and targeting a specific subset
by regex (e.g. for workflow_dispatch).

Adapted from polkadot-sdk's .github/scripts/parse-zombienet-tests.py.

Usage:
    parse-zombienet-tests.py --matrix tests.yml \
        [--flaky-tests flaky.txt] [--test-pattern regex]
"""

import argparse
import json
import re

import yaml


def parse_args():
    parser = argparse.ArgumentParser(description="Parse test matrix YAML file with optional filtering")
    parser.add_argument("--matrix", required=True, help="Path to the YAML matrix file")
    parser.add_argument("--flaky-tests", default="", help="Newline-separated list of flaky job names")
    parser.add_argument("--test-pattern", default="", help="Regex pattern to match job_name")
    return parser.parse_args()


def load_jobs(matrix_path):
    with open(matrix_path, "r") as f:
        return yaml.safe_load(f)


def filter_jobs(jobs, flaky_tests, test_pattern):
    flaky_set = set(name.strip() for name in flaky_tests.splitlines() if name.strip())
    filtered = []

    for job in jobs:
        name = job.get("job-name", "")

        # If a test_pattern is provided the user explicitly asked for that
        # subset — don't skip flaky entries that match the pattern.
        if test_pattern:
            if re.search(test_pattern, name):
                filtered.append(job)
        elif name not in flaky_set:
            filtered.append(job)

    return filtered


def main():
    args = parse_args()
    jobs = load_jobs(args.matrix)
    result = filter_jobs(jobs, args.flaky_tests, args.test_pattern)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
