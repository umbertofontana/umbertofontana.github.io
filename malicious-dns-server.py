#!/usr/bin/env python3
import socket
from collections import defaultdict
from dnslib import DNSRecord, RR, A, CNAME, QTYPE, RCODE

# ---------------------------------------------------
# INLINE ZONES
# - A_CYCLIC:
#     first_ips: returned ALL at cycle step 0 (4 A records)
#     next_ip:   returned at cycle steps 1..4 (1 A record)
# - CNAME:
#     target: canonical name
# ---------------------------------------------------
ZONES = {
    "example.com.": {
        "type": "A_CYCLIC",
        "first_ips": [
            "185.194.144.144",
            "185.194.144.145"
        ],
        "next_ip": "127.0.0.1",
    },

    # CNAME pointing to the cyclic A above
    "example.com.": {
        "type": "CNAME",
        "target": "example.github.io",
    }
}

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53  # high port -> fewer conflicts on Windows

# counters only make sense for A_CYCLIC names
QUERY_COUNTER = defaultdict(int)


def debug(msg):
    print(f"[DEBUG] {msg}")


def pick_cyclic_a_ips(qname):
    """
    5-step cycle:
      step 0: return 4 IPs
      step 1..4: return single IP
    then repeat.
    """
    count = QUERY_COUNTER[qname]
    slot = count % 5
    zone = ZONES[qname]

    if slot == 0:
        ips = zone["first_ips"]
        phase = "first-phase (4 A records)"
    else:
        ips = [zone["next_ip"]]
        phase = f"second-phase (1 A record) step {slot+1}/5"

    QUERY_COUNTER[qname] += 1

    debug(
        f"{qname} query #{count+1} -> {ips} [{phase}] "
        f"(next count will be {QUERY_COUNTER[qname]})"
    )
    return ips


def resolve_a_for_name(qname, max_depth=3):
    """
    Returns (answers, cname_chain)
    - answers: list of RR (A records)
    - cname_chain: list of RR (CNAMEs we had to emit)
    This lets us answer A queries even when the name is a CNAME.
    """
    answers = []
    cname_chain = []
    current_name = qname
    depth = 0

    while depth < max_depth:
        zone = ZONES.get(current_name)
        if not zone:
            # name not found
            break

        if zone["type"] == "A_CYCLIC":
            # produce A records according to cycle
            ips = pick_cyclic_a_ips(current_name)
            for ip in ips:
                answers.append(
                    RR(
                        rname=current_name,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=1,
                        rdata=A(ip),
                    )
                )
            break  # done

        elif zone["type"] == "CNAME":
            target = zone["target"]
            # add CNAME to chain
            cname_chain.append(
                RR(
                    rname=current_name,
                    rtype=QTYPE.CNAME,
                    rclass=1,
                    ttl=60,
                    rdata=CNAME(target),
                )
            )
            # follow to target
            current_name = target
            depth += 1
        else:
            # unknown type -> stop
            break

    return answers, cname_chain


def build_response(data, addr):
    try:
        request = DNSRecord.parse(data)
    except Exception as e:
        debug(f"Failed to parse packet from {addr}: {e}")
        return None

    if not request.questions:
        debug("No question in request")
        return None

    q = request.questions[0]
    qname = str(q.qname)
    qtype = q.qtype
    qtype_name = QTYPE.get(qtype, "UNKNOWN")

    debug(f"Query from {addr}: name={qname} type={qtype_name}")

    reply = request.reply()
    reply.header.aa = 1  # authoritative

    zone = ZONES.get(qname)

    # 1) If we don't know the name -> NXDOMAIN
    if not zone:
        debug(f"{qname} not found, NXDOMAIN")
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    # 2) If the query is CNAME
    if qtype == QTYPE.CNAME:
        if zone["type"] == "CNAME":
            target = zone["target"]
            debug(f"Returning CNAME {qname} -> {target}")
            reply.add_answer(
                RR(
                    rname=q.qname,
                    rtype=QTYPE.CNAME,
                    rclass=1,
                    ttl=60,
                    rdata=CNAME(target),
                )
            )
            return reply
        elif zone["type"] == "A_CYCLIC":
            # they asked for CNAME but it's an A name: just say NOERROR/no answer
            debug(f"{qname} is A_CYCLIC but asked for CNAME, replying empty NOERROR")
            return reply

    # 3) If the query is A
    if qtype == QTYPE.A:
        # delegate to resolver that can walk CNAMEs
        answers, cname_chain = resolve_a_for_name(qname)

        if not answers and not cname_chain:
            # we know the name but couldn't produce A -> NOERROR empty
            debug(f"{qname} known but no A produced, sending empty NOERROR")
            return reply

        # order: CNAMEs first, then A
        for rr in cname_chain:
            reply.add_answer(rr)
        for rr in answers:
            reply.add_answer(rr)

        return reply

    # 4) Any other type: just return NOERROR empty
    debug(f"Unsupported qtype={qtype_name}, replying empty NOERROR")
    return reply


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # so we can restart easily
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    debug(f"DNS server (dnslib) listening on {LISTEN_IP}:{LISTEN_PORT}")

    while True:
        data, addr = sock.recvfrom(512)
        debug(f"---\nRaw packet ({len(data)} bytes) from {addr}")
        resp = build_response(data, addr)
        if resp is not None:
            wire = resp.pack()
            debug(f"Sending {len(wire)} bytes to {addr}")
            sock.sendto(wire, addr)
        else:
            debug("No response generated")


if __name__ == "__main__":
    main()
