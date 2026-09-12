#include "utils.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>  // IWYU pragma: keep
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

namespace netscan {

NetworkInterface NetworkInterface::fetch(uint32_t target_base_ip, uint32_t total_hosts) {
    NetworkInterface interface{};

    // Ask the kernel which local address it would use to route Internet traffic.
    // A UDP socket is used to perform a route lookup without sending any packets
    sockaddr_in probe{};
    probe.sin_family = AF_INET;
    uint16_t const default_dns_port = 53;
    probe.sin_port = htons(default_dns_port);
    // NOTE: default_dns_ip can be any public DNS IP (e.g., 1.1.1.1 for Cloudflare, 8.8.8.8 for Google, etc)
    char const* const default_dns_ip = "1.1.1.1";
    inet_pton(AF_INET, default_dns_ip, &probe.sin_addr);

    int const sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return interface;
    }

    sockaddr_in local{};
    socklen_t local_len = sizeof(local);

    // Let the kernel select the source address for the route, then retrieve it
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    bool const routed = connect(sock, reinterpret_cast<sockaddr*>(&probe), sizeof(probe)) == 0 &&
                        getsockname(sock, reinterpret_cast<sockaddr*>(&local), &local_len) == 0;
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

    close(sock);

    if (!routed) {
        return interface;
    }

    uint32_t const local_ip = ntohl(local.sin_addr.s_addr);

    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        return interface;
    }

    uint32_t const target_end_ip =
        (total_hosts == 0) ? target_base_ip : target_base_ip + static_cast<uint32_t>(total_hosts - 1);

    // Match the kernel selected source address to its interface and network details
    for (struct ifaddrs const* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_netmask == nullptr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        if (((ifa->ifa_flags & IFF_UP) == 0U) || ((ifa->ifa_flags & IFF_LOOPBACK) != 0U) ||
            ((ifa->ifa_flags & IFF_BROADCAST) == 0U)) {
            continue;
        }

        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const* addr_in = reinterpret_cast<sockaddr_in const*>(ifa->ifa_addr);
        auto const* mask_in = reinterpret_cast<sockaddr_in const*>(ifa->ifa_netmask);
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

        uint32_t const current_ip = ntohl(addr_in->sin_addr.s_addr);

        // Match the source address selected by the kernel.
        if (current_ip != local_ip) {
            continue;
        }

        uint32_t const mask = ntohl(mask_in->sin_addr.s_addr);
        uint32_t const network_ip = current_ip & mask;
        uint32_t const broadcast_ip = current_ip | ~mask;

        interface.name = ifa->ifa_name;
        interface.ip_address = current_ip;
        interface.network_ip = network_ip;
        interface.broadcast_ip = broadcast_ip;

        interface.is_local = target_base_ip <= broadcast_ip && target_end_ip >= network_ip;

        std::array<char, INET_ADDRSTRLEN> host{};

        if (inet_ntop(AF_INET, &addr_in->sin_addr, host.data(), host.size()) != nullptr) {
            interface.ip = host.data();
        }

        in_addr network_addr{};
        network_addr.s_addr = htonl(network_ip);
        if (inet_ntop(AF_INET, &network_addr, host.data(), host.size()) != nullptr) {
            interface.network = host.data();
        }

        in_addr broadcast_addr{};
        broadcast_addr.s_addr = htonl(broadcast_ip);
        if (inet_ntop(AF_INET, &broadcast_addr, host.data(), host.size()) != nullptr) {
            interface.broadcast = host.data();
        }

        freeifaddrs(ifaddr);
        return interface;
    }

    freeifaddrs(ifaddr);
    return interface;
}

void format_ip(uint32_t ip_address, char* buf, size_t len) {
    in_addr addr{};
    addr.s_addr = htonl(ip_address);
    inet_ntop(AF_INET, &addr, buf, static_cast<socklen_t>(len));
}

bool parse_cidr(char const* input, uint32_t& out_base_ip, uint32_t& out_count) {
    if (input == nullptr) {
        return false;
    }

    std::string const input_str(input);
    auto const slash_pos = input_str.find('/');

    if (slash_pos == std::string::npos) {
        in_addr addr{};
        if (inet_pton(AF_INET, input_str.c_str(), &addr) != 1) {
            return false;
        }

        out_base_ip = ntohl(addr.s_addr);
        out_count = 1;
        return true;
    }

    std::string const ip_str = input_str.substr(0, slash_pos);
    in_addr addr{};
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return false;
    }

    std::string const prefix_str = input_str.substr(slash_pos + 1);
    if (prefix_str.empty()) {
        return false;
    }

    char* mutable_end_ptr = nullptr;  // NOLINT(misc-const-correctness)
    int64_t const prefix_long = static_cast<int64_t>(std::strtol(prefix_str.c_str(), &mutable_end_ptr, 10));
    char const* const end_ptr = mutable_end_ptr;

    // Ensure parsing happened and the entire string was consumed (end_ptr hits the null-terminator)
    if (end_ptr == prefix_str.c_str() || *end_ptr != '\0') {
        return false;
    }

    if (prefix_long < 0 || prefix_long > BITS_IN_IPV4) {
        return false;
    }

    auto const prefix = static_cast<int>(prefix_long);

    uint32_t const base = ntohl(addr.s_addr);
    uint32_t const mask = (prefix == 0) ? 0U : (~0U << static_cast<uint32_t>(BITS_IN_IPV4 - prefix));

    out_base_ip = base & mask;
    out_count = (prefix == BITS_IN_IPV4) ? 1U : (~mask + 1U);

    return true;
}

std::string resolve_hostname(uint32_t ip_address) {
    sockaddr_in sock_addr{};
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(ip_address);

    std::array<char, NI_MAXHOST> host{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    int const res = getnameinfo(reinterpret_cast<struct sockaddr*>(&sock_addr), sizeof(sock_addr), host.data(),
                                static_cast<socklen_t>(host.size()), nullptr, 0, 0);

    if (res == 0) {
        return {host.data()};
    }

    return "N/A";
}

}  // namespace netscan
