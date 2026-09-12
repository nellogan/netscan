<div align="center">

# netscan

[![CI-x86_64 Status](https://github.com/nellogan/netscan/actions/workflows/CI-x86_64.yml/badge.svg)](https://github.com/nellogan/netscan/actions/workflows/CI-x86_64.yml)
[![CI-aarch64 Status](https://github.com/nellogan/netscan/actions/workflows/CI-aarch64.yml/badge.svg)](https://github.com/nellogan/netscan/actions/workflows/CI-aarch64.yml)

</div>

Netscan is a high performance Linux IPv4 network host discovery and scanning
tool. It performs ICMP ping scans, TCP scans, and ARP table inspection without
requiring root privileges.

## Features
- **Unprivileged:** designed to run without root access.
- **ICMP discovery:** sweep IPv4 networks using ICMP Echo Requests.
- **TCP scanning:** discover hosts with a specified TCP port open.
- **ARP inspection:** inspect the local kernel ARP/neighbor table.
- **Reverse DNS:** optionally resolve discovered IP addresses to hostnames.
- **IPv4 utilities:** quickly determine the local LAN address, network address, and broadcast address.

## Usage
```text
    netscan --help
    Usage: netscan [OPTION...] [CIDR]
    netscan -- a high-performance Linux IPv4 network host discovery and scanning
    tool. It performs ICMP ping scans, TCP scans, and ARP table inspection without
    requiring root privileges.
    
      -B, --broadcast            Print network broadcast IPv4 address and exit
      -c, --probes=NUM           Max concurrent probes (default: 4096)
      -d, --dns=0|1              Enable/Disable reverse DNS resolution (default:
                                 1)
      -l, --payload=BYTES        ICMP payload length (default: 56)
      -L, --local-ip             Print local LAN IPv4 address and exit
      -m, --mode=MODE            Select scan/operation mode: ping, tcp, arp
                                 (default: ping)
      -N, --network              Print network base IPv4 address and exit
      -p, --port=PORT            Target port for TCP mode (default: 443)
      -r, --recv-batch=NUM       Receive batch size (default: 128)
      -s, --send-batch=NUM       Send batch size (default: 4)
      -t, --timeout=MS           Max timeout / RTT in ms (default: 800)
      -?, --help                 Give this help list
          --usage                Give a short usage message
      -V, --version              Print program version
```

## Getting Started

```bash
git clone https://github.com/nellogan/netscan.git
cd netscan
make
./bin/default/netscan --help
./bin/default/netscan 192.168.1.0/24
```

## Modes
### ARP Table

Inspect the cached ARP/neighbor table for hosts already known to the local system:

```bash
./bin/default/netscan -m arp
```

Example output:

```text
IP ADDRESS      | MAC ADDRESS       | INTERFACE  | HOSTNAME                      
------------------------------------------------------------------------------------
192.168.1.1     | ab:cd:ef:12:34:56 | wlo1       | 192.168.1.1                   
192.168.1.14    | 78:90:ab:cd:ef:12 | wlo1       | 192.168.1.14 
192.168.1.42    | 34:56:78:90:ab:cd | wlo1       | 192.168.1.42 
------------------------------------------------------------------------------------
```

### ICMP Ping Scan
        
Perform an ICMP Echo sweep across an IPv4 CIDR range:

```bash
./bin/default/netscan -m ping 192.168.1.0/24
```

Example output:

```text
[*] Starting ICMP Ping Scan on 256 hosts from 192.168.1.0/24 (payload=0, probes=4096, timeout_ms=1200, send_batch=4, recv_batch=128, dns=true)

[+] IP: 192.168.1.1     | Hostname: 192.168.1.1                              | RTT:   7.06 ms | TTL:  64
[+] IP: 192.168.1.14    | Hostname: 192.168.1.14                             | RTT:   7.59 ms | TTL:  64
[+] IP: 192.168.1.42    | Hostname: 192.168.1.42                             | RTT:   0.10 ms | TTL:  64

========================================
        ICMP PING SCAN COMPLETE        
========================================
Total unique responsive hosts found : 3
Total scan time                     : 1.314 seconds
TX Throttles / Drops                : 0
RX Queue Overflows                  : 0
ICMP Echo Replies Received          : 3
Unmatched Echo Replies              : 0
Probe Timeouts                      : 251
========================================

```

The default scan mode is ping, so the mode can also be omitted:

```bash
./bin/default/netscan 192.168.1.0/24
```

### TCP Scan

Scan for hosts with a specific TCP port accepting connections. For example, 
to find hosts with HTTPS available on port 443:

```bash
./bin/default/netscan -m tcp -p 443 192.168.1.0/24
```

Example output:

```text
[*] Starting TCP Scan on 256 hosts from 192.168.1.0/24 (Port: 443, probes=4096, timeout_ms=2000ms, send_batch=4, dns=true)

[+] IP: 192.168.1.1     | Hostname: 192.168.1.1                              | Port: 443   | RTT: 5.8 ms | OPEN

========================================
       TCP SCAN COMPLETE        
========================================
Target Port                         : 443
Total unique open hosts found       : 1
Total scan time                     : 2.073 seconds
========================================
```

## Performance

The following benchmarks compare Netscan against roughly equivalent nmap scans on a /24 LAN.

### ICMP Ping Scan

Approximate nmap equivalent:

```bash
sudo nmap -T5 -n -sn -PE --disable-arp-ping --max-retries 0 "$CIDR"
```

Benchmark:

```bash
./benchmark.sh -c "$CIDR" -b nmap -m ping
./benchmark.sh -c "$CIDR" -b netscan -m ping
```

Example results:

```text
=== Benchmarking PING Sweep (192.168.1.0/24 using nmap) ===
Scan Time: 3.67 seconds

=== Benchmarking PING Sweep (192.168.1.0/24 using netscan) ===
Scan Time: 1.28 seconds
```

Result: Netscan was approximately ~2.87 times faster for this /24 LAN scan.

### TCP Scan

Approximate nmap equivalent:

```bash
nmap -T5 -n -sT -Pn -p "$PORT" --disable-arp-ping --max-retries 0 "$CIDR"
```

Benchmark:

```bash
./benchmark.sh -c "$CIDR" -b nmap -m tcp -p "$PORT"
./benchmark.sh -c "$CIDR" -b netscan -m tcp -p "$PORT"
```

Example results:

```text
=== Benchmarking TCP Sweep (192.168.1.0/24 using nmap) ===
Scan Time: 0.85 seconds

=== Benchmarking TCP Sweep (192.168.1.0/24 using netscan) ===
Scan Time: 0.67 seconds
```

Result: Netscan was approximately ~1.27 times faster for this /24 LAN scan.

NOTE: Benchmark results are workload and network dependent. These measurements are representative and should not be 
interpreted as universal performance guarantees.

## Tuning

Netscan exposes several options for tuning scan performance:

    --probes: maximum number of concurrent probes.
    --timeout: maximum probe timeout in milliseconds.
    --send-batch: number of packets sent per batch.
    --recv-batch: number of packets received per batch.
    --dns: enable or disable reverse DNS resolution.
    --payload: configure the ICMP payload size.

For example:

```bash
./bin/default/netscan \
  --probes 4096 \
  --timeout 800 \
  --send-batch 16 \
  --recv-batch 256 \
  --dns 0 \
  192.168.1.0/24
```

## Testing

### Native Local Testing

Format and lint the source:

```bash
make format
make lint
```

Run the test suite with AddressSanitizer, LeakSanitizer, and UndefinedBehaviorSanitizer:

```bash
make CONFIG=xsan test
```

Run the test suite with MemorySanitizer:

```bash
make CONFIG=msan test
```

Run the test suite under Valgrind:

```bash
make test-valgrind
```

### Containerized Testing

Run the containerized test suite locally:

```bash
bash ./container-test.sh
```

The containerized tests cover native x86_64 execution as well as AArch64 execution through emulation.
