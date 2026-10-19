#!/usr/bin/env python3
"""
Email Authentication Checker

Looks up a domain's SPF, DKIM, and DMARC DNS records and grades its email
authentication posture - the same three mechanisms mailbox providers
(Gmail, Outlook, etc.) use to decide whether to trust, quarantine, or
reject mail claiming to be from a domain.

Usage:
    python3 checker.py example.com
    python3 checker.py example.com --dkim-selectors google,selector1,selector2
    python3 checker.py domains.txt --json report.json
"""

import sys
import json
import argparse

import dns.resolver
import dns.exception

from checks import check_spf, check_dkim, check_dmarc, grade_from_score

COMMON_DKIM_SELECTORS = [
    "google", "default", "selector1", "selector2", "k1", "mail",
    "dkim", "smtp", "mandrill", "mailgun",
]


def make_resolver(nameservers=None, port=53, timeout=5):
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.port = port
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def lookup_txt(resolver, name):
    """Returns a list of TXT record strings for `name`, or [] if the name
    doesn't exist / has no TXT records. Raises on genuine DNS errors
    (timeout, SERVFAIL) so callers can tell 'no record' from 'couldn't check'."""
    try:
        answer = resolver.resolve(name, "TXT")
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    records = []
    for rdata in answer:
        # Each TXT record can be split across multiple quoted strings -
        # join them back into one string, same as how receivers parse it.
        parts = [s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                  for s in rdata.strings]
        records.append("".join(parts))
    return records


def check_domain(domain, resolver, dkim_selectors):
    result = {"domain": domain, "errors": []}

    try:
        spf_txt = lookup_txt(resolver, domain)
        result["spf"] = check_spf(spf_txt)
    except (dns.exception.DNSException, Exception) as e:
        result["errors"].append(f"SPF lookup failed: {e}")
        result["spf"] = None

    try:
        selector_results = {}
        for sel in dkim_selectors:
            recs = lookup_txt(resolver, f"{sel}._domainkey.{domain}")
            selector_results[sel] = recs[0] if recs else None
        result["dkim"] = check_dkim(selector_results)
    except (dns.exception.DNSException, Exception) as e:
        result["errors"].append(f"DKIM lookup failed: {e}")
        result["dkim"] = None

    try:
        dmarc_txt = lookup_txt(resolver, f"_dmarc.{domain}")
        result["dmarc"] = check_dmarc(dmarc_txt)
    except (dns.exception.DNSException, Exception) as e:
        result["errors"].append(f"DMARC lookup failed: {e}")
        result["dmarc"] = None

    checks = [c for c in (result["spf"], result["dkim"], result["dmarc"]) if c is not None]
    if checks:
        score = round(100 * sum(c.points for c in checks) / sum(c.max_points for c in checks))
    else:
        score = None
    result["score"] = score
    result["grade"] = grade_from_score(score) if score is not None else None
    return result


def print_report(result):
    print(f"\n{result['domain']}")
    if result["score"] is not None:
        print(f"  Overall grade: {result['grade']}  (score: {result['score']}/100)")
    else:
        print("  Could not complete any checks (see errors below)")

    for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
        check = result[key]
        if check is None:
            continue
        tag = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}[check.status]
        print(f"  [{tag}] {name}")
        print(f"         {check.message}")

    for err in result["errors"]:
        print(f"  [ERROR] {err}")


def main():
    parser = argparse.ArgumentParser(description="Check a domain's SPF, DKIM, and DMARC configuration.")
    parser.add_argument("target", help="A domain name, or a path to a text file with one domain per line")
    parser.add_argument("--dkim-selectors", default=",".join(COMMON_DKIM_SELECTORS),
                         help="Comma-separated DKIM selectors to probe (DKIM selectors can't be discovered via DNS alone)")
    parser.add_argument("--nameserver", action="append", help="DNS server(s) to query instead of the system resolver")
    parser.add_argument("--port", type=int, default=53, help="DNS port to query (default 53; used by tests to point at a local fixture server)")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report to FILE")
    args = parser.parse_args()

    selectors = [s.strip() for s in args.dkim_selectors.split(",") if s.strip()]
    resolver = make_resolver(args.nameserver, port=args.port)

    try:
        with open(args.target) as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except (OSError, IOError):
        domains = [args.target]

    results = []
    worst_grade_rank = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4, None: 5}
    exit_code = 0

    for domain in domains:
        result = check_domain(domain, resolver, selectors)
        print_report(result)
        results.append(result)
        if result["grade"] in ("D", "F") or result["grade"] is None:
            exit_code = 1

    if args.json:
        serializable = []
        for r in results:
            entry = {"domain": r["domain"], "score": r["score"], "grade": r["grade"], "errors": r["errors"]}
            for key in ("spf", "dkim", "dmarc"):
                check = r[key]
                entry[key] = None if check is None else {
                    "status": check.status, "message": check.message,
                    "points": check.points, "max_points": check.max_points,
                }
            serializable.append(entry)
        with open(args.json, "w") as f:
            json.dump(serializable, f, indent=2)
        print(f"\nJSON report written to {args.json}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
