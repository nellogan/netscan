#ifndef UTILS_HPP
#define UTILS_HPP

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <string>

/*
Socket options & constants
Linux UAPI:
// SO_RXQ_OVFL: https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/socket.h#L61
SO_RXQ_OVFL = 40
// IP_RECVTTL: https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h#L112
IP_RECVTTL = 12
// ICMP_ECHOREPLY: https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h#L26
ICMP_ECHOREPLY = 0
// ICMP_ECHO: https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h#L30
ICMP_ECHO = 8
*/

namespace netscan {

inline constexpr double NANOSECONDS_PER_SECOND_D = 1000000000.0;
inline constexpr int64_t NANOSECONDS_PER_SECOND_LL = 1000000000LL;
inline constexpr double NANOSECONDS_PER_MILLISECOND_D = 1000000.0;
inline constexpr int64_t NANOSECONDS_PER_MILLISECOND_LL = 1000000LL;

inline constexpr int EPOLL_TIMEOUT_MS = 1;

inline constexpr size_t CIDR_BUFFER_SIZE = 64;
inline constexpr int BITS_IN_IPV4 = 32;

inline constexpr size_t DEFAULT_PAYLOAD_LEN = 0;
inline constexpr uint8_t PAYLOAD_CHAR_OFFSET = 10;
inline constexpr uint8_t PAYLOAD_CHAR_MOD = 26;

inline constexpr int DEFAULT_PING_TIMEOUT_MS = 800;
inline constexpr int DEFAULT_TCP_TIMEOUT_MS = 600;

inline constexpr int DEFAULT_MAX_PROBES = 4096;

inline constexpr int DEFAULT_PING_SEND_BATCH_SIZE = 4;
inline constexpr int DEFAULT_PING_RECV_BATCH_SIZE = 128;

inline constexpr int DEFAULT_TCP_PORT = 443;
inline constexpr int DEFAULT_TCP_BATCH_SIZE = 64;

inline constexpr bool DEFAULT_RESOLVE_DNS = true;

// Assume 1500 byte MTU and padded to 2048
inline constexpr size_t MAX_RX_PACKET_SIZE = 2048;

struct NetworkInterface {
    std::string name;
    std::string ip;
    std::string network;
    std::string broadcast;

    uint32_t ip_address{0};
    uint32_t network_ip{0};
    uint32_t broadcast_ip{0};

    bool is_local{false};

    static NetworkInterface fetch(uint32_t target_base_ip, uint32_t total_hosts);
};

constexpr size_t safe_batch_size(size_t val, size_t max_hosts) {
    size_t const limit = std::min(val, max_hosts);
    return std::min(limit, static_cast<size_t>(UINT_MAX));
}

void format_ip(uint32_t ip_address, char* buf, size_t len);

bool parse_cidr(char const* input, uint32_t& out_base_ip, uint32_t& out_count);

std::string resolve_hostname(uint32_t ip_address);

}  // namespace netscan

#endif  // UTILS_HPP