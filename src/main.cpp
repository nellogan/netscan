#include <argp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>  // NOLINT(modernize-deprecated-headers)

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "arp_table.hpp"
#include "ping_scanner.hpp"
#include "tcp_scanner.hpp"
#include "utils.hpp"

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
char const* argp_program_version = "netscan 1.0.0";
char const* argp_program_bug_address = "https://github.com/nellogan/netscan/issues";
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

constexpr char const* DOC =
    "netscan -- a high-performance Linux IPv4 network host discovery and scanning tool. It performs ICMP ping "
    "scans, TCP scans, and ARP table inspection without requiring root privileges.";

constexpr char const* ARGS_DOC = "[CIDR]";

constexpr std::array<argp_option, 12> OPTIONS{{
    {"mode", 'm', "MODE", 0, "Select scan/operation mode: ping, tcp, arp (default: ping)", 0},
    {"port", 'p', "PORT", 0, "Target port for TCP mode (default: 443)", 0},
    {"payload", 'l', "BYTES", 0, "ICMP payload length (default: 0)", 0},
    {"probes", 'c', "NUM", 0, "Max concurrent probes (default: 4096)", 0},
    {"timeout", 't', "MS", 0, "Max timeout / RTT in ms (default: 800 (ping), 600 (tcp))", 0},
    {"send-batch", 's', "NUM", 0, "Send batch size (default: 4)", 0},
    {"recv-batch", 'r', "NUM", 0, "Receive batch size (default: 128)", 0},
    {"dns", 'd', "0|1", 0, "Enable/Disable reverse DNS resolution (default: 1)", 0},
    {"local-ip", 'L', nullptr, 0, "Print local LAN IPv4 address and exit", 0},
    {"broadcast", 'B', nullptr, 0, "Print network broadcast IPv4 address and exit", 0},
    {"network", 'N', nullptr, 0, "Print network base IPv4 address and exit", 0},
    {nullptr, 0, nullptr, 0, nullptr, 0},
}};

struct Config {
    std::string cidr_arg;
    std::string mode{"ping"};
    uint16_t port{netscan::DEFAULT_TCP_PORT};
    size_t payload_len{netscan::DEFAULT_PAYLOAD_LEN};
    size_t max_probes{netscan::DEFAULT_MAX_PROBES};
    uint32_t timeout_ms{0};  // 0 = use mode-specific default
    size_t send_batch{netscan::DEFAULT_PING_SEND_BATCH_SIZE};
    size_t recv_batch{netscan::DEFAULT_PING_RECV_BATCH_SIZE};
    bool resolve_dns{netscan::DEFAULT_RESOLVE_DNS};
    bool print_local_ip{false};
    bool print_broadcast_ip{false};
    bool print_network_ip{false};
};

namespace {

int parse_opt(int key, char* arg, struct argp_state* state) {
    auto* config = static_cast<Config*>(state->input);

    // NOLINTBEGIN(readability-magic-numbers)
    switch (key) {
        case 'm':
            config->mode = arg;
            break;
        case 'p':
            config->port = static_cast<uint16_t>(std::strtoul(arg, nullptr, 10));
            break;
        case 'l':
            config->payload_len = static_cast<size_t>(std::strtoul(arg, nullptr, 10));
            break;
        case 'c':
            config->max_probes = static_cast<size_t>(std::strtoul(arg, nullptr, 10));
            break;
        case 't':
            config->timeout_ms = static_cast<uint32_t>(std::strtoul(arg, nullptr, 10));
            break;
        case 's':
            config->send_batch = static_cast<size_t>(std::strtoul(arg, nullptr, 10));
            break;
        case 'r':
            config->recv_batch = static_cast<size_t>(std::strtoul(arg, nullptr, 10));
            break;
        case 'd':
            config->resolve_dns = (std::strtoul(arg, nullptr, 10) != 0);
            break;
        case 'L':
            config->print_local_ip = true;
            break;
        case 'B':
            config->print_broadcast_ip = true;
            break;
        case 'N':
            config->print_network_ip = true;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 1) {
                argp_usage(state);  // NOLINT(concurrency-mt-unsafe)
            }
            config->cidr_arg = arg;
            break;
        case ARGP_KEY_END:
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    // NOLINTEND(readability-magic-numbers)
    return 0;
}

const struct argp ARGP_PARSER = {OPTIONS.data(), parse_opt, ARGS_DOC, DOC, nullptr, nullptr, nullptr};

int handle_arp_mode(bool resolve_dns) {
    std::printf("[*] Querying system ARP table via Netlink (dns=%s)...\n\n", resolve_dns ? "true" : "false");
    auto arp_entries = netscan::get_arp_table();

    if (arp_entries.empty()) {
        std::printf("[*] No ARP entries found in kernel cache.\n");
        return 0;
    }

    std::printf("%-15s | %-17s | %-10s | %-30s\n", "IP ADDRESS", "MAC ADDRESS", "INTERFACE", "HOSTNAME");
    std::printf("------------------------------------------------------------------------------------\n");

    for (auto const& entry : arp_entries) {
        in_addr addr{};
        addr.s_addr = htonl(entry.ip);

        std::array<char, INET_ADDRSTRLEN> ip_str{};
        inet_ntop(AF_INET, &addr, ip_str.data(), ip_str.size());

        std::string hostname{"N/A"};
        if (resolve_dns) {
            hostname = netscan::resolve_hostname(entry.ip);
        }

        std::printf("%-15s | %-17s | %-10s | %-30s\n", ip_str.data(), entry.mac_address.c_str(),
                    entry.iface_name.c_str(), hostname.c_str());
    }
    std::printf("------------------------------------------------------------------------------------\n");
    std::printf("[+] Total cached ARP entries: %zu\n", arp_entries.size());
    return 0;
}

int execute_network_scan(Config const& config) {
    uint32_t base_ip{0};
    uint32_t total_hosts{0};
    if (!netscan::parse_cidr(config.cidr_arg.c_str(), base_ip, total_hosts)) {
        (void)std::fprintf(stderr, "Invalid CIDR specification: %s\n", config.cidr_arg.c_str());
        return 1;
    }

    // Resolve timeout: if user didn't specify (-t), use mode-specific default
    uint32_t timeout_ms = config.timeout_ms;
    if (timeout_ms == 0) {
        timeout_ms = (config.mode == "tcp") ? netscan::DEFAULT_TCP_TIMEOUT_MS : netscan::DEFAULT_PING_TIMEOUT_MS;
    }

    if (config.mode == "ping") {
        std::printf(
            "[*] Starting ICMP Ping Scan on %u hosts from %s (payload=%zu, probes=%zu, timeout_ms=%u, "
            "send_batch=%zu, recv_batch=%zu, dns=%s)\n\n",
            total_hosts, config.cidr_arg.c_str(), config.payload_len, config.max_probes, timeout_ms, config.send_batch,
            config.recv_batch, config.resolve_dns ? "true" : "false");

        netscan::PingScannerConfig const scanner_config{
            base_ip,
            total_hosts,
            config.payload_len,
            config.max_probes,
            timeout_ms,
            config.send_batch,
            config.recv_batch,
            config.resolve_dns,
            [](netscan::PingHostResult const& res) {
                std::printf("[+] IP: %-15s | Hostname: %-40s | RTT: %6.2f ms | TTL: %3d\n", res.ip_str.c_str(),
                            res.hostname.c_str(), res.rtt_ms, res.ttl);
            }};

        timespec scan_start_time{};
        clock_gettime(CLOCK_REALTIME, &scan_start_time);  // NOLINT(misc-include-cleaner)

        netscan::PingScanner scanner(scanner_config);
        auto results = scanner.run();

        timespec scan_end_time{};
        clock_gettime(CLOCK_REALTIME, &scan_end_time);
        double const total_scan_time_sec =
            static_cast<double>(scan_end_time.tv_sec - scan_start_time.tv_sec) +
            (static_cast<double>(scan_end_time.tv_nsec - scan_start_time.tv_nsec) / netscan::NANOSECONDS_PER_SECOND_D);

        std::printf("\n========================================\n");
        std::printf("        ICMP PING SCAN COMPLETE        \n");
        std::printf("========================================\n");
        std::printf("Total unique responsive hosts found : %zu\n", results.hosts.size());
        std::printf("Total scan time                     : %.3f seconds\n", total_scan_time_sec);
        std::printf("TX Throttles / Drops                : %u\n", results.tx_drops);
        std::printf("RX Queue Overflows                  : %u\n", results.rx_queue_overflows);
        std::printf("ICMP Echo Replies Received          : %u\n", results.echo_replies);
        std::printf("Unmatched Echo Replies              : %u\n", results.unmatched_replies);
        std::printf("Probe Timeouts                      : %u\n", results.probe_timeouts);
        std::printf("========================================\n");

    } else if (config.mode == "tcp") {
        std::printf(
            "[*] Starting TCP Scan on %u hosts from %s (Port: %u, probes=%zu, timeout_ms=%u, send_batch=%zu, "
            "dns=%s)\n\n",
            total_hosts, config.cidr_arg.c_str(), config.port, config.max_probes, timeout_ms, config.send_batch,
            config.resolve_dns ? "true" : "false");

        netscan::TcpScannerConfig const scanner_config{
            base_ip,
            total_hosts,
            config.port,
            config.max_probes,
            timeout_ms,
            config.send_batch,
            config.resolve_dns,
            [](netscan::TcpHostResult const& res) {
                std::printf("[+] IP: %-15s | Hostname: %-40s | Port: %-5u | RTT: %6.2f ms | OPEN\n", res.ip_str.c_str(),
                            res.hostname.c_str(), res.port, res.rtt_ms);
            }};

        timespec scan_start_time{};
        clock_gettime(CLOCK_REALTIME, &scan_start_time);

        netscan::TcpScanner scanner(scanner_config);
        auto results = scanner.run();

        timespec scan_end_time{};
        clock_gettime(CLOCK_REALTIME, &scan_end_time);
        double const total_scan_time_sec =
            static_cast<double>(scan_end_time.tv_sec - scan_start_time.tv_sec) +
            (static_cast<double>(scan_end_time.tv_nsec - scan_start_time.tv_nsec) / netscan::NANOSECONDS_PER_SECOND_D);

        std::printf("\n========================================\n");
        std::printf("       TCP SCAN COMPLETE        \n");
        std::printf("========================================\n");
        std::printf("Target Port                         : %u\n", config.port);
        std::printf("Total unique open hosts found       : %zu\n", results.size());
        std::printf("Total scan time                     : %.3f seconds\n", total_scan_time_sec);
        std::printf("========================================\n");

    } else {
        (void)std::fprintf(stderr, "Unknown scan mode: %s. Use 'ping', 'tcp', or 'arp'.\n", config.mode.c_str());
        return 1;
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Config config;

    argp_parse(&ARGP_PARSER, argc, argv, 0, nullptr, &config);  // NOLINT(concurrency-mt-unsafe)

    if (config.print_local_ip || config.print_broadcast_ip || config.print_network_ip) {
        uint32_t base_ip{0};
        uint32_t total_hosts{0};

        if (!config.cidr_arg.empty()) {
            if (!netscan::parse_cidr(config.cidr_arg.c_str(), base_ip, total_hosts)) {
                (void)std::fprintf(stderr, "Invalid CIDR specification: %s\n", config.cidr_arg.c_str());
                return 1;
            }
        }

        auto interface = netscan::NetworkInterface::fetch(base_ip, total_hosts);

        if (interface.ip.empty() || interface.network.empty() || interface.broadcast.empty()) {
            (void)std::fprintf(stderr, "Error: Could not determine local network interface.\n");
            return 1;
        }

        if (config.print_local_ip) {
            std::printf("%s\n", interface.ip.c_str());
        }

        if (config.print_broadcast_ip) {
            std::printf("%s\n", interface.broadcast.c_str());
        }

        if (config.print_network_ip) {
            std::printf("%s\n", interface.network.c_str());
        }

        return 0;
    }

    if (config.mode == "arp") {
        return handle_arp_mode(config.resolve_dns);
    }

    if (config.cidr_arg.empty()) {
        (void)std::fprintf(stderr, "Error: No target CIDR or IP specified. Run with --help for usage.\n");
        return 1;
    }

    return execute_network_scan(config);
}
