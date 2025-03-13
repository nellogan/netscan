## Install
    git clone https://github.com/nellogan/netscan.git
    #Optionally run tests first: make test-sanitizers && make clean-all && make test-valgrind
    make
    make clean
    sudo make install
    #Optionally add to path via bashrc:
    #echo 'export PATH="$PATH:/usr/local/netscan/bin"' >> ~/.bashrc

## Uninstall
    sudo make uninstall
    #Do not forget to remove 'PATH="$PATH:/usr/local/netscan/bin"' from ~/.bashrc

## Examples
Note: if not added to path replace 'netscan' with './bin/netscan'.

### Get help:

    netscan --help
    Usage: netscan [OPTION...] IP_ADDR_OR_CIDR
    netscan -- scan either an IPv4 address or a range of IPv4 addresses (CIDR notation)
    at port 443(HTTPS). By default, will attempt a TCP connection. Send ICMP
    packet(s) (via ping) if the -p switch is provided instead. Particularly useful
    for scanning a LAN subnet (assuming permission to do so). This program is a
    proof of concept and not as powerful as nmap but is straight forward,
    lightweight, and host discovery (even if ping is not available). Requires the
    'ping' commandline program to be installed to use the -p switch.
    
      -p, --ping_toggle          Toggle that will attempt a TCP connection in lieu
                                 of a ping to determine if host or hosts are up.
      -?, --help                 Give this help list
          --usage                Give a short usage message
      -V, --version              Print program version
    
    Report bugs to <https://github.com/nellogan/netscan/issues>.

### Scan a single IPv4 address
Try scanning Google's public DNS IPv4 address:

    netscan 8.8.8.8

#### Result:

    Host(s) found:
        IP Addr: 8.8.8.8,               hostname: dns.google

### Scan a range of IPv4 addresses using the Classless Inter-Domain Routing (CIDR) notation. 
Here, Google's public DNS IPv4 address (8.8.8.8) and two other Google IPv4 addresses 8.8.8.9 and 8.8.8.10 are scanned 
by passing "8.8.8.8/30". Since these two additional addresses do not respond to TCP connections or ping (ICMP) requests, 
they will not be reported as "found."

    netscan 8.8.8.8/30
    
#### Result:

    Host(s) found:
        IP Addr: 8.8.8.8,               hostname: dns.google


### Send ping requests instead of TCP connection attempts:

    netscan -p 8.8.8.8/30

#### Result:

    Host(s) found:
        IP Addr: 8.8.8.8,               hostname: dns.google

## Notes

TCP connection attempts will not be retransmitted for faster scanning. Linux generally sets the initial threshold to 1
second. Here socket send timeout is set to 0.05 seconds so no re-transmissions will occur. Scanning a common subnet of 
/24 (255 hosts) will take a maximum of 12.75 seconds assuming all 255 hosts were actually sent TCP SYN requests while 
ping attempts will take a maximum of 254 seconds (1 second timeout). Generally the connect scan method will return much 
sooner than 12.75 seconds due to ARP requests requiring a response (if not in cache) before bothering to send a TCP SYN 
packet. 

The valgrind suppressions file in ./suppression is added due to an avahi bug where calling getnameinfo() will leak to 
reachable memory when the DNS cannot resolve the requested IP address. Reproducible by attempting to call getnameinfo() 
on a loopback address such as 127.233.233.233.
