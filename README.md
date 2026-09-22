# SBT-DF203-Lab7: DNS Introduction and Traffic Analysis

A formal digital forensics investigation analyzing Domain Name System (DNS) resolution mechanics, query/response structure, and network connection correlation. This lab establishes a normal DNS baseline-evaluating transaction IDs, record types (A, AAAA, MX, NS), TTL cache lifetimes, and browser/application query inventories using `dig`, `tshark`, and `wireshark`.

---

## 📌 Investigation Overview

- **Lead Examiner:** Nebeuwa Ifeanyichukwu Raphael
- **Course & Lab:** SBT-DF203 - Basic Networking Skills for Digital Forensics (Lab 7)
- **Primary Tools:** `dig` (`dnsutils`), `tshark`, `wireshark`, `resolvectl`, `sha256sum`
- **Environment:** Kali Linux VM running in an authorized, isolated virtual environment

### Key Analytical Findings
- **Resolver & Evidence Integrity:** System resolver configurations were dumped via `/etc/resolv.conf` and `resolvectl status`. Baseline reference capture (`evidence/dig_dns.pcap`) and fresh captures (`evidence/fresh_dig_dns.pcapng`) were hashed using SHA-256 to ensure forensic chain-of-custody.
- **DNS Record Profiling:** `dig` queries successfully extracted `A` (IPv4), `AAAA` (IPv6), `MX` (Mail Exchange), and `NS` (Name Server) records. Evaluated TTL fields as dynamic cache countdown timers rather than record creation timestamps.
- **Packet-Level Field Extraction:** Filtered `dns.flags.response == 0` (queries) and `dns.flags.response == 1` (responses) over UDP port 53. Validated 1:1 query-to-response mapping via the 16-bit DNS Transaction ID (`dns.id`) and endpoint 4-tuple matching.
- **Connection Correlation:** Correlated DNS `A` record answers (`dns.a`) with subsequent TCP `SYN` packets (`tcp.flags.syn == 1 && tcp.flags.ack == 0`) to confirm application connection origins (e.g., HTTP/HTTPS sessions following domain lookups).

---

## 📁 Repository Structure

```text
SBT-DF203-Lab7/
├── evidence/
│   ├── dig_dns.pcap                 # Original reference DNS packet capture
│   ├── fresh_dig_dns.pcapng         # Controlled fresh dig DNS capture
│   └── browser_dns.pcapng           # Packet capture of browser/application DNS traffic
├── working/
│   └── dig_dns_working.pcap         # Working copy of reference capture for analysis
├── reports/
│   ├── resolv_conf.txt              # Exported system resolver configuration
│   ├── resolvectl_status.txt        # Systemd-resolved status output
│   ├── dns_capture_hashes.txt       # SHA-256 verification log for capture evidence
│   ├── dig_example_A.txt            # dig A record query log
│   ├── dig_example_AAAA.txt         # dig AAAA record query log
│   ├── dig_example_MX.txt           # dig MX record query log
│   ├── dig_example_NS.txt           # dig NS record query log
│   ├── dns_queries.tsv              # Extracted packet fields for DNS queries
│   ├── dns_responses.tsv            # Extracted packet fields for DNS responses
│   ├── browser_dns_inventory.txt    # Frequency-sorted inventory of browser DNS queries
│   ├── dns_A_answers.tsv            # Extracted DNS A record resolutions with timestamps
│   ├── subsequent_tcp_destinations.tsv # Captured outbound TCP SYN connection attempts
│   └── smtp_dns_correlation.tsv     # (Optional) DNS MX lookup correlation from SMTP evidence
└── README.md
```
## ⚙️ Execution & Methodology

**1. Evidence Directory Setup & Resolver Baseline**

Establish the standardized workspace, verify system DNS resolvers, and validate evidence integrity:

```Bash
mkdir -p ~/SBT-DF203-Lab7/{evidence,working,exported,reports,screenshots,scripts}
cd ~/SBT-DF203-Lab7

# Document configured system resolvers
cat /etc/resolv.conf | tee reports/resolv_conf.txt
resolvectl status 2>/dev/null | tee reports/resolvectl_status.txt || true

# Obtain reference evidence copy and verify integrity hashes
wget -O evidence/dig_dns.pcap '[https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Networking_Forensics/lab_files/dns/dig_dns.pcap](https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Networking_Forensics/lab_files/dns/dig_dns.pcap)'
cp --preserve=timestamps evidence/dig_dns.pcap working/dig_dns_working.pcap
sha256sum evidence/dig_dns.pcap working/dig_dns_working.pcap | tee reports/dns_capture_hashes.txt
```

**2. Perform Controlled DNS Queries (dig)**

Query A, AAAA, MX, and NS record types to inspect answer structure, flags, status codes, and TTL values:

```Bash
dig example.com A | tee reports/dig_example_A.txt
dig example.com AAAA | tee reports/dig_example_AAAA.txt
dig example.com MX | tee reports/dig_example_MX.txt
dig example.com NS | tee reports/dig_example_NS.txt
dig +short example.com A | tee reports/dig_example_short.txt
```

**3. Capture Fresh DNS Traffic & Extract Packet Fields**

Capture live UDP port 53 traffic during controlled dig execution and extract header fields with tshark:

```Bash
IFACE=eth0

# Background capture for 25 seconds
sudo tshark -i "$IFACE" -f 'port 53' -a duration:25 -w evidence/fresh_dig_dns.pcapng &
sleep 3
dig +noedns example.com A >/dev/null
wait

# Hash the newly created capture
sha256sum evidence/fresh_dig_dns.pcapng | tee reports/fresh_dns_sha256.txt

# Extract DNS Query Fields (dns.flags.response == 0)
PCAP=evidence/fresh_dig_dns.pcapng
tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields \
  -e frame.number -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport \
  -e dns.id -e dns.qry.name -e dns.qry.type \
  | tee reports/dns_queries.tsv

# Extract DNS Response Fields (dns.flags.response == 1)
tshark -r "$PCAP" -Y 'dns.flags.response==1' -T fields \
  -e frame.number -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport \
  -e dns.id -e dns.flags.rcode -e dns.count.answers -e dns.a -e dns.aaaa -e dns.resp.ttl \
  | tee reports/dns_responses.tsv
```
  
**4. Browser DNS Inventory & Outbound IP Connection Correlation**

Capture complex multi-domain web traffic and correlate resolved IP addresses with subsequent TCP SYN requests:

```Bash
# Capture browser DNS activity
sudo tshark -i "$IFACE" -f 'port 53' -a duration:40 -w evidence/browser_dns.pcapng &
sleep 3
# Navigate to approved website in private browser session
wait

# Generate unique domain query inventory
tshark -r evidence/browser_dns.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name -e dns.qry.type \
  | sort | uniq -c | sort -nr | tee reports/browser_dns_inventory.txt

# Extract resolved IPv4 addresses from DNS answers
tshark -r evidence/browser_dns.pcapng -Y 'dns.a' -T fields \
  -e frame.time_epoch -e dns.qry.name -e dns.a \
  | tee reports/dns_A_answers.tsv

# Extract subsequent TCP SYN handshake attempts
tshark -r evidence/browser_dns.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields \
  -e frame.time_epoch -e ip.dst -e tcp.dstport \
  | tee reports/subsequent_tcp_destinations.tsv
```



