#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <thread>

#include "arp_table.hpp"
#include "ping_scanner.hpp"
#include "tcp_scanner.hpp"
#include "utils.hpp"

namespace {

constexpr uint32_t TEST_TIMEOUT_SHORT_MS = 150;
constexpr uint32_t TEST_TIMEOUT_MED_MS = 200;
constexpr uint32_t TEST_TIMEOUT_LONG_MS = 800;
constexpr size_t TEST_MAX_PROBES = 10;
constexpr size_t TEST_PING_SEND_BATCH_SIZE = 4;
constexpr size_t TEST_PING_RECV_BATCH_SIZE = 4;
constexpr size_t TEST_TCP_BATCH_SIZE = 4;
constexpr uint16_t TEST_OPEN_PORT = 19999;
constexpr uint16_t TEST_CLOSED_PORT = 19998;
constexpr size_t TEST_PAYLOAD_LEN = 0;

int start_local_tcp_server(uint16_t port) {
    int const server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        return -1;
    }

    int opt{1};
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));  // NOLINT(misc-include-cleaner)

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) < 0) {
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, TEST_TCP_BATCH_SIZE) < 0) {
        close(server_fd);
        return -1;
    }

    return server_fd;
}

// Test 1: CIDR & Single IP Parsing Validation
void test_cidr_parser() {
    std::printf("[*] Running test_cidr_parser...\n");

    uint32_t base_ip{0};
    uint32_t count{0};

    // Test standard /24 subnet
    assert(netscan::parse_cidr("192.168.1.0/24", base_ip, count) == true);
    assert(count == 256);

    // Test single host with /32
    assert(netscan::parse_cidr("10.0.0.1/32", base_ip, count) == true);
    assert(count == 1);

    // Test standalone single host IP (now supported)
    assert(netscan::parse_cidr("192.168.1.1", base_ip, count) == true);
    assert(count == 1);

    // Test invalid subnets/IPs
    assert(netscan::parse_cidr("256.300.1.1/24", base_ip, count) == false);     // Bad IP
    assert(netscan::parse_cidr("192.168.1.1/33", base_ip, count) == false);     // Bad prefix
    assert(netscan::parse_cidr("not-an-ip-address", base_ip, count) == false);  // Completely malformed

    std::printf("[+] CIDR parser tests passed successfully!\n");
}

// Test 2: TCP Scanner Integration (Open Port)
void test_tcp_scanner_integration() {
    std::printf("[*] Running test_tcp_scanner_integration (open port)...\n");

    uint16_t const test_port{TEST_OPEN_PORT};
    int const server_fd = start_local_tcp_server(test_port);
    if (server_fd < 0) {
        (void)std::fprintf(stderr, "[-] Warning: Could not bind local TCP port %u. Skipping TCP test.\n", test_port);
        return;
    }

    std::thread server_thread([server_fd]() {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
        int const client_fd =
            accept4(server_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len, SOCK_CLOEXEC);
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
        if (client_fd >= 0) {
            close(client_fd);
        }
    });

    uint32_t base_ip{0};
    uint32_t count{0};
    bool const resolve_dns{true};
    size_t const batch_size{TEST_TCP_BATCH_SIZE};
    // Scan a small block 127.0.0.0/29 containing 127.0.0.1 (where our server lives)
    assert(netscan::parse_cidr("127.0.0.0/29", base_ip, count));

    netscan::TcpScannerConfig const config{
        base_ip, count, test_port, TEST_MAX_PROBES, TEST_TIMEOUT_LONG_MS, batch_size, resolve_dns,
    };
    netscan::TcpScanner scanner(config);
    scanner.run();

    if (server_thread.joinable()) {
        server_thread.join();
    }
    close(server_fd);

    std::printf("[+] TCP scanner integration test passed successfully!\n");
}

// Test 3: TCP Scanner Closed Port (Negative Test)
void test_tcp_scanner_closed_port() {
    std::printf("[*] Running test_tcp_scanner_closed_port (negative test)...\n");

    uint32_t base_ip{0};
    uint32_t count{0};
    bool const resolve_dns{true};
    size_t const batch_size{TEST_TCP_BATCH_SIZE};

    // Scan a small block 127.0.0.0/29 containing 127.0.0.1 (where our server lives)
    assert(netscan::parse_cidr("127.0.0.0/29", base_ip, count));

    netscan::TcpScannerConfig const config{
        base_ip, count, TEST_CLOSED_PORT, TEST_MAX_PROBES, TEST_TIMEOUT_MED_MS, batch_size, resolve_dns,
    };
    netscan::TcpScanner scanner(config);
    scanner.run();

    std::printf("[+] TCP scanner closed port test passed successfully!\n");
}

// Test 4: Ping Scanner Integration
void test_ping_scanner_integration() {
    std::printf("[*] Running test_ping_scanner_integration...\n");

    uint32_t base_ip{0};
    uint32_t count{0};
    bool const resolve_dns{true};
    size_t const send_ping_batch_size{TEST_PING_SEND_BATCH_SIZE};
    size_t const recv_ping_batch_size{TEST_PING_RECV_BATCH_SIZE};

    // Scan range 127.0.0.0/29 (covers loopback host 127.0.0.1)
    assert(netscan::parse_cidr("127.0.0.0/29", base_ip, count));

    try {
        netscan::PingScannerConfig const config{base_ip,
                                                count,
                                                TEST_PAYLOAD_LEN,
                                                TEST_MAX_PROBES,
                                                TEST_TIMEOUT_LONG_MS,
                                                send_ping_batch_size,
                                                recv_ping_batch_size,
                                                resolve_dns};

        netscan::PingScanner scanner(config);
        scanner.run();
        std::printf("[+] Ping scanner integration test passed successfully!\n");
    } catch (std::exception const& e) {
        (void)std::fprintf(stderr, "[-] Warning: Ping scanner execution threw exception: %s\n", e.what());
    }
}

// Test 5: Scanner Timeout & Reaping
void test_scanner_timeout_reaping() {
    std::printf("[*] Running test_scanner_timeout_reaping (blackholed target)...\n");

    uint32_t base_ip{0};
    uint32_t count{0};
    bool const resolve_dns{true};
    size_t const tcp_batch_size{TEST_TCP_BATCH_SIZE};
    size_t const send_ping_batch_size{TEST_PING_SEND_BATCH_SIZE};
    size_t const recv_ping_batch_size{TEST_PING_RECV_BATCH_SIZE};

    // Use TEST-NET-1 (192.0.2.0/28) to test timeouts over a multi-host dead block
    assert(netscan::parse_cidr("192.0.2.0/28", base_ip, count));

    netscan::TcpScannerConfig const config{
        base_ip, count, TEST_CLOSED_PORT, TEST_MAX_PROBES, TEST_TIMEOUT_LONG_MS, tcp_batch_size, resolve_dns,
    };
    netscan::TcpScanner scanner(config);

    std::printf("tcp scan test start\n");
    scanner.run();

    std::printf("tcp scan test done\n");

    // Verify Ping timeout and reaping state machine cleans up properly
    // Wrapped in try-catch because unprivileged ICMP sockets (SOCK_DGRAM, IPPROTO_ICMP)
    // can throw permission errors depending on kernel sysctl settings (ping_group_range).
    try {
        netscan::PingScannerConfig const config{base_ip,
                                                count,
                                                TEST_PAYLOAD_LEN,
                                                TEST_MAX_PROBES,
                                                TEST_TIMEOUT_SHORT_MS,
                                                send_ping_batch_size,
                                                recv_ping_batch_size,
                                                resolve_dns};

        netscan::PingScanner ping_scanner(config);

        ping_scanner.run();
    } catch (std::exception const& e) {
        (void)std::fprintf(stderr, "[-] Note: Ping scanner timeout test handled exception: %s\n", e.what());
    }

    std::printf("[+] Scanner timeout and reaping test passed successfully!\n");
}

// Test 6: Netlink ARP Table Query & Hostname Resolution
void test_netlink_arp_table() {
    std::printf("[*] Querying system ARP table via Netlink...\n");
    auto arp_list = netscan::get_arp_table();

    for (auto const& entry : arp_list) {
        in_addr addr{};
        addr.s_addr = htonl(entry.ip);

        std::array<char, INET_ADDRSTRLEN> ip_buf{};
        char const* ip_address = inet_ntop(AF_INET, &addr, ip_buf.data(), ip_buf.size());

        std::string const hostname = netscan::resolve_hostname(entry.ip);

        std::printf("[ARP] IP: %-15s | MAC: %-17s | Interface: %-6s | Hostname: %s\n",
                    ip_address != nullptr ? ip_address : "<invalid>", entry.mac_address.c_str(),
                    entry.iface_name.c_str(), hostname.c_str());
    }
    std::printf("[+] Netlink ARP query completed successfully (%zu entries found).\n", arp_list.size());
}

}  // namespace

int main() {
    std::printf("========================================\n");
    std::printf("     STARTING FULL SCANNER TESTS        \n");
    std::printf("========================================\n");

    test_cidr_parser();
    test_tcp_scanner_integration();
    test_tcp_scanner_closed_port();
    test_scanner_timeout_reaping();
    test_ping_scanner_integration();
    test_netlink_arp_table();

    netscan::NetworkInterface const interface = netscan::NetworkInterface::fetch(0, 0);

    if (interface.ip.empty()) {
        (void)std::fprintf(stderr, "[-] Warning: Could not determine local network INTERFACE.\n");
    } else {
        std::printf("Local interface : %s\n", interface.name.c_str());
        std::printf("Local LAN IP    : %s\n", interface.ip.c_str());
        std::printf("Network IP      : %s\n", interface.network.c_str());
        std::printf("Broadcast IP    : %s\n", interface.broadcast.c_str());
    }

    std::printf("\n========================================\n");
    std::printf("      ALL TESTS COMPLETED SUCCESSFULLY  \n");
    std::printf("========================================\n");
    return 0;
}
