#!/usr/bin/env bash
set -euo pipefail

#./benchmark.sh -c 192.168.1.0/24 -b netscan -p 443
#./benchmark.sh -c 192.168.1.0/24 -b nmap -p 443
#./benchmark.sh -c 192.168.1.0/24 -b netscan -m ping
#./benchmark.sh -c 192.168.1.0/24 -b nmap -m ping

# Default values
PORT="443"
BINARY="nmap"
CIDR=""
MODE="ping"
NETWORK_IP="192.168.1.0"
RANGE="24"

# Usage function
usage() {
    echo "Usage: $0 [-c <CIDR>] [-b <binary>] [-p <port>] [-m <mode>]"
    echo "  -c    CIDR network string (default: auto-detected via netscan -N + /${RANGE}, or fallback to ${NETWORK_IP}/${RANGE})"
    echo "  -b    Executable binary: nmap or netscan (default: nmap)"
    echo "  -p    TCP port to scan (default: 443)"
    echo "  -m    Scan mode: tcp or ping (default: tcp)"
    exit 1
}

# Parse command-line arguments
while getopts "c:b:p:m:h" opt; do
    case "$opt" in
        c) CIDR="$OPTARG" ;;
        b) BINARY="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# If CIDR is not given, try auto-detecting via netscan, otherwise use the default IP/range
if [ -z "$CIDR" ]; then
    if DETECTED_IP="$(./bin/default/netscan -N 2>/dev/null)"; then
        CIDR="${DETECTED_IP}/${RANGE}"
    else
        CIDR="${NETWORK_IP}/${RANGE}"
    fi
fi

MODE_UP=$(echo "$MODE" | tr '[:lower:]' '[:upper:]')

echo "=== Benchmarking ${MODE_UP} Sweep ($CIDR using $BINARY) ==="
echo -n "Scan Time: "

case "$BINARY" in
    nmap)
        if [ "$MODE" = "ping" ]; then
            ( time -p sudo nmap -T5 -n -sn -PE --disable-arp-ping --max-retries 0 "$CIDR" > /dev/null 2>&1 ) 2>&1 | grep real | awk '{print $2 " seconds"}'
        elif [ "$MODE" = "tcp" ]; then
            ( time -p nmap -T5 -n -sT -Pn -p "$PORT" --disable-arp-ping --max-retries 0 "$CIDR" > /dev/null 2>&1 ) 2>&1 | grep real | awk '{print $2 " seconds"}'
        else
            echo "Error: Unsupported nmap mode '$MODE'."
            exit 1
        fi
        ;;
    netscan)
        if [ "$MODE" = "ping" ]; then
            ( time -p ./bin/default/netscan -d 0 -m ping "$CIDR" > /dev/null 2>&1 ) 2>&1 | grep real | awk '{print $2 " seconds"}'
        elif [ "$MODE" = "tcp" ]; then
            ( time -p ./bin/default/netscan -d 0 -m tcp -p "$PORT" "$CIDR" > /dev/null 2>&1 ) 2>&1 | grep real | awk '{print $2 " seconds"}'
        else
            echo "Error: Unsupported netscan mode '$MODE'."
            exit 1
        fi
        ;;
    *)
        echo "Error: Unsupported binary configuration for '$BINARY'."
        exit 1
        ;;
esac
