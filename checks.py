"""
The actual SPF / DKIM / DMARC parsing and scoring logic - kept separate
from DNS lookups and the CLI so it can be unit-tested directly with known
record strings, independent of the network.
"""

import re

# --- Result objects -------------------------------------------------------

class CheckResult:
    def __init__(self, status, message, points, max_points):
        self.status = status      # "pass" | "warn" | "fail"
        self.message = message
        self.points = points
        self.max_points = max_points

    def __repr__(self):
        return f"<{self.status.upper()} {self.message!r} ({self.points}/{self.max_points})>"


# --- SPF -------------------------------------------------------------------

def check_spf(txt_records):
    """txt_records: list of raw TXT record strings for the domain itself."""
    spf_records = [r for r in txt_records if r.strip().lower().startswith("v=spf1")]

    if not spf_records:
        return CheckResult("fail", "No SPF record found - anyone can spoof mail 'from' this domain with no SPF check at all.", 0, 25)

    if len(spf_records) > 1:
        return CheckResult("fail", f"Multiple SPF records found ({len(spf_records)}) - RFC 7208 requires exactly one; receivers may treat this as a permanent SPF failure.", 0, 25)

    spf = spf_records[0].strip()

    # Count DNS-lookup mechanisms (include/a/mx/ptr/exists) - SPF has a
    # hard limit of 10 lookups (RFC 7208 4.6.4); past that, receivers must
    # treat the whole record as a PermError.
    lookup_count = len(re.findall(r"[+\-~?]?(?:include|exists):[^\s]+|[+\-~?]?(?:a|mx|ptr)(?::|(?=[\s$]))", spf))

    all_match = re.search(r"([+\-~?])all\b", spf)
    qualifier = all_match.group(1) if all_match else None

    if qualifier is None:
        return CheckResult("warn", f"SPF record has no 'all' mechanism at the end - its policy for everything else is undefined. Record: {spf}", 12, 25)

    if qualifier == "+":
        return CheckResult("fail", f"SPF ends in '+all' - this explicitly allows ANY server to send mail as this domain, defeating the purpose of SPF entirely. Record: {spf}", 0, 25)

    if lookup_count > 10:
        return CheckResult("warn", f"SPF record has {lookup_count} DNS-lookup mechanisms - RFC 7208 caps this at 10; some receivers will reject it as a PermError. Record: {spf}", 15, 25)

    if qualifier == "-":
        return CheckResult("pass", f"SPF record present with strict '-all' (hard fail). Record: {spf}", 25, 25)

    if qualifier == "~":
        return CheckResult("pass", f"SPF record present with '~all' (soft fail) - reasonable, though '-all' is stricter. Record: {spf}", 22, 25)

    # qualifier == "?"
    return CheckResult("warn", f"SPF ends in '?all' (neutral) - equivalent to having no policy for unlisted senders. Record: {spf}", 10, 25)


# --- DKIM -------------------------------------------------------------------

def check_dkim(selector_results):
    """
    selector_results: dict of {selector_name: txt_record_or_None}, one
    entry per DKIM selector that was looked up (e.g. 'google', 'default',
    'selector1', 'selector2', 'k1', 'mail').
    """
    found = {sel: rec for sel, rec in selector_results.items() if rec}

    if not found:
        checked = ", ".join(selector_results.keys())
        return CheckResult("warn", f"No DKIM record found under common selectors ({checked}). DKIM selectors are arbitrary and chosen by the mail provider, so this isn't conclusive - check your provider's setup docs for the exact selector they use.", 10, 25)

    problems = []
    for sel, rec in found.items():
        rec_lower = rec.lower()
        if "p=" not in rec_lower:
            problems.append(f"{sel}: no 'p=' public key tag found")
            continue
        p_match = re.search(r"p=([^;]*)", rec, re.IGNORECASE)
        key_value = p_match.group(1).strip() if p_match else ""
        if key_value == "":
            problems.append(f"{sel}: 'p=' is empty - this selector's key has been revoked")

    if problems:
        return CheckResult("warn", f"DKIM selector(s) found but with issues: {'; '.join(problems)}", 15, 25)

    return CheckResult("pass", f"Valid DKIM record found under selector(s): {', '.join(found.keys())}", 25, 25)


# --- DMARC -------------------------------------------------------------------

def check_dmarc(txt_records):
    """txt_records: list of raw TXT record strings for _dmarc.<domain>."""
    dmarc_records = [r for r in txt_records if r.strip().lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return CheckResult("fail", "No DMARC record found at _dmarc.<domain> - without DMARC, SPF/DKIM results aren't enforced and spoofed mail that fails both can still be delivered.", 0, 25)

    if len(dmarc_records) > 1:
        return CheckResult("fail", f"Multiple DMARC records found ({len(dmarc_records)}) - RFC 7489 requires exactly one; receivers may ignore all of them.", 0, 25)

    dmarc = dmarc_records[0].strip()

    p_match = re.search(r"[;\s]p=([^;]+)", ";" + dmarc, re.IGNORECASE)
    policy = p_match.group(1).strip().lower() if p_match else None

    pct_match = re.search(r"[;\s]pct=(\d+)", ";" + dmarc, re.IGNORECASE)
    pct = int(pct_match.group(1)) if pct_match else 100

    rua_present = bool(re.search(r"[;\s]rua=", ";" + dmarc, re.IGNORECASE))

    if policy is None:
        return CheckResult("fail", f"DMARC record present but missing required 'p=' policy tag. Record: {dmarc}", 5, 25)

    if policy == "none":
        note = " No aggregate reports (rua=) configured either, so there's no visibility into who's sending mail as this domain." if not rua_present else " Aggregate reports (rua=) are configured, which is a reasonable first step while moving toward enforcement."
        return CheckResult("warn", f"DMARC policy is 'p=none' (monitor only - spoofed mail is still delivered, just reported).{note} Record: {dmarc}", 12, 25)

    if pct < 100:
        return CheckResult("warn", f"DMARC policy is 'p={policy}' but only applied to {pct}% of mail (pct={pct}) - the rest is exempt from enforcement. Record: {dmarc}", 18, 25)

    if policy == "quarantine":
        return CheckResult("pass", f"DMARC policy is 'p=quarantine' at 100% - failing mail is sent to spam. Record: {dmarc}", 22, 25)

    if policy == "reject":
        return CheckResult("pass", f"DMARC policy is 'p=reject' at 100% - the strictest setting; failing mail is rejected outright. Record: {dmarc}", 25, 25)

    return CheckResult("warn", f"DMARC record present with unrecognized policy value 'p={policy}'. Record: {dmarc}", 10, 25)


def grade_from_score(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
