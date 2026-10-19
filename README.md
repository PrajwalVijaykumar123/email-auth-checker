# Email Authentication Checker

Looks up a domain's SPF, DKIM, and DMARC DNS records and grades its email authentication posture — the same three mechanisms Gmail, Outlook, and every other major mailbox provider use to decide whether to trust, quarantine, or reject mail claiming to be from that domain.

## What This Project Does

- **Three real DNS lookups per domain**: SPF (a TXT record on the domain itself), DKIM (TXT records under common selector names, since DKIM selectors aren't discoverable via DNS alone), and DMARC (a TXT record at `_dmarc.<domain>`)
- **Checks the actual policy, not just presence**: an SPF record that ends in `+all` is *worse* than no SPF at all (it explicitly authorizes any server), and a DMARC record with `p=none` provides monitoring but no enforcement — both of these would pass a naive "does the record exist" check and fail this one
- **Flags RFC-violating configurations**: multiple SPF records (undefined behavior per RFC 7208), more than 10 DNS-lookup mechanisms in an SPF record (receivers must treat it as a PermError past that), a DMARC record missing its required `p=` tag
- **A 0–100 score and A–F grade** per domain, with every finding explained
- **Batch mode**: point it at a text file of domains instead of a single one

## Why presence alone isn't enough

Every one of these three mechanisms has a configured-but-useless form. `v=spf1 +all` is a valid SPF record that disables SPF's entire purpose. `v=DMARC1; p=none` is a valid DMARC record that reports on spoofing without blocking any of it. A scanner that only checks "is there a TXT record here" would give both of these a passing grade. This tool parses the actual mechanism and policy values, the same way a receiving mail server does.

## Example Output

```
good-domain.test
  Overall grade: A  (score: 100/100)
  [PASS] SPF
         SPF record present with strict '-all' (hard fail). Record: v=spf1 include:_spf.good-domain.test -all
  [PASS] DKIM
         Valid DKIM record found under selector(s): selector1
  [PASS] DMARC
         DMARC policy is 'p=reject' at 100% - the strictest setting; failing mail is rejected outright. Record: v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@good-domain.test

bad-domain.test
  Overall grade: F  (score: 13/100)
  [FAIL] SPF
         SPF ends in '+all' - this explicitly allows ANY server to send mail as this domain, defeating the purpose of SPF entirely. Record: v=spf1 +all
  [WARN] DKIM
         No DKIM record found under common selectors (google, default, selector1, ...)
  [FAIL] DMARC
         No DMARC record found at _dmarc.<domain> - without DMARC, SPF/DKIM results aren't enforced and spoofed mail that fails both can still be delivered.
```

(Real output from the test suite's local DNS fixtures — see Testing below.)

## Tech Stack

- Python 3.11
- `dnspython` for real DNS resolution

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```bash
python3 checker.py example.com
python3 checker.py example.com --dkim-selectors google,selector1,selector2
python3 checker.py domains.txt --json report.json
```

DKIM selectors are chosen by whoever set up the mail provider and can't be found via DNS alone — the tool probes a list of common ones (`google`, `default`, `selector1`, `selector2`, `k1`, `mail`, `dkim`, `smtp`, `mandrill`, `mailgun`) by default; pass `--dkim-selectors` with your provider's actual selector for a conclusive result.

## Testing

Real DNS lookups depend on live records that change over time and on network access the test environment may not have, so for a deterministic, repeatable test, `test_fixtures/test_dns_server.py` spins up a real local authoritative DNS server (using `dnslib`) with four fixed-posture test domains — good (grade A), partial (soft-fail SPF, monitor-only DMARC), bad (`+all` SPF, no DMARC), and none (no records at all):

```bash
pip install -r test_fixtures/requirements-test.txt
sh test_fixtures/run_test.sh
```

This runs the real `checker.py` against the real DNS server over actual UDP queries on `127.0.0.1` — not a mocked resolver — and verifies each domain lands on its expected grade and that the specific `+all` misconfiguration gets its own flagged warning rather than a generic low score.

## Architecture

```
dns.resolver.Resolver().resolve(name, "TXT")  <-- real DNS query
        |
        v
checker.py: three lookups per domain
  domain            -> SPF
  _dmarc.domain     -> DMARC
  sel._domainkey.domain (per selector) -> DKIM
        |
        v
checks.py: parse + score each record independently
  SPF:   qualifier (-all/~all/?all/+all), lookup-mechanism count, duplicate records
  DKIM:  p= tag present and non-empty, per selector
  DMARC: p= policy, pct= enforcement percentage, rua= reporting
        |
        v
Weighted score (25 pts each) -> 0-100 -> A-F grade -> console report + optional JSON
```

## Project Structure

```
email-auth-checker/
├── checker.py                   # CLI: DNS lookups, batch mode, reporting
├── checks.py                     # SPF/DKIM/DMARC parsing and scoring (pure logic, no network)
├── requirements.txt
└── test_fixtures/
    ├── test_dns_server.py        # Real local authoritative DNS server with fixed test records
    ├── run_test.sh                 # Starts the server, runs checker.py against it, verifies grades
    └── requirements-test.txt      # dnslib, only needed to run the test suite
```

## What I Learned

- Why "is the record present" and "is the record actually effective" are different questions for all three of SPF, DKIM, and DMARC — each has a syntactically valid, fully-present configuration that provides zero real protection (`+all`, an empty DKIM key, `p=none`), and a checker that doesn't parse the actual values would miss all three
- DKIM is structurally different from SPF/DMARC in a way that matters for tooling: SPF and DMARC live at well-known, fixed DNS names, but DKIM selectors are provider-chosen and not discoverable by DNS alone — a DKIM "not found" result is genuinely inconclusive in a way the other two aren't, and the tool's reporting has to say that rather than implying a definite fail
- Building a real local DNS server for testing (rather than mocking the resolver function) turned out to be just as easy as the local HTTP server used in an earlier project, and tests a real code path — the actual UDP query/response cycle — instead of stopping at the parsing logic

## Next Steps

- MTA-STS and TLS-RPT checks, which cover the transport-security side of email authentication that SPF/DKIM/DMARC don't touch
- Resolve the SPF `include:` chain recursively and report the real total lookup count, rather than only counting mechanisms in the top-level record
- A BIMI (Brand Indicators for Message Identification) check, since mailbox providers increasingly tie logo display to DMARC enforcement level
