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

