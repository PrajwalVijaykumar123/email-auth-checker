"""
A tiny local authoritative DNS server, used only for testing. It answers
real UDP DNS queries over the wire with known, fixed records for a
handful of fake test domains covering each grade (A/B/F) - so checker.py
exercises its real dnspython resolver code path against a real DNS
server, not a mocked function.
"""

import threading
from dnslib import RR, QTYPE, TXT
from dnslib.server import DNSServer, DNSLogger

# domain -> { "TXT" or "DKIM:<selector>" -> [record strings] }
RECORDS = {
    # Good posture: strict SPF, DKIM present, DMARC reject at 100%
    "good-domain.test": {
        "TXT": ["v=spf1 include:_spf.good-domain.test -all"],
        "DKIM:selector1": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"],
        "DMARC": ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@good-domain.test"],
    },
    # Partial posture: soft-fail SPF, no DKIM found, DMARC monitor-only
    "partial-domain.test": {
        "TXT": ["v=spf1 include:_spf.partial-domain.test ~all"],
        "DMARC": ["v=DMARC1; p=none"],
    },
    # Bad posture: permissive SPF, no DKIM, no DMARC at all
    "bad-domain.test": {
        "TXT": ["v=spf1 +all"],
    },
    # No records of any kind
    "none-domain.test": {},
}


class FixtureResolver:
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        if qtype != "TXT":
            return reply  # NOERROR, no answers - fine for our purposes

        if qname.startswith("_dmarc."):
            domain = qname[len("_dmarc."):]
            for txt in RECORDS.get(domain, {}).get("DMARC", []):
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt), ttl=60))
        elif "._domainkey." in qname:
            selector, domain = qname.split("._domainkey.", 1)
            for txt in RECORDS.get(domain, {}).get(f"DKIM:{selector}", []):
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt), ttl=60))
        else:
            for txt in RECORDS.get(qname, {}).get("TXT", []):
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt), ttl=60))

        return reply


def start_server(port=15353, quiet=True):
    logger = DNSLogger(log="", prefix=False) if quiet else DNSLogger(prefix=False)
    server = DNSServer(FixtureResolver(), port=port, address="127.0.0.1", logger=logger)
    server.start_thread()
    return server


if __name__ == "__main__":
    srv = start_server()
    print("Test DNS server running on 127.0.0.1:15353 (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.stop()
