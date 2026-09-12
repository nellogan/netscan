#include "arp_table.hpp"

#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "utils.hpp"

namespace netscan {

void parse_netlink_attributes(struct rtattr* rta, unsigned int rta_len, uint32_t& ip_address, std::string& mac) {
    constexpr size_t mac_str_len = 18;
    constexpr size_t mac_byte_count = 6;

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        if (rta->rta_type == NDA_DST) {
            uint32_t addr{0};
            std::memcpy(&addr, RTA_DATA(rta), sizeof(addr));
            ip_address = ntohl(addr);
        } else if (rta->rta_type == NDA_LLADDR) {
            if (RTA_PAYLOAD(rta) < mac_byte_count) {
                return;
            }

            std::array<uint8_t, mac_byte_count> mac_bytes{};
            std::memcpy(mac_bytes.data(), RTA_DATA(rta), mac_bytes.size());

            std::array<char, mac_str_len> mac_buf{};
            int const written =
                std::snprintf(mac_buf.data(), mac_buf.size(), "%02x:%02x:%02x:%02x:%02x:%02x", mac_bytes.at(0),
                              mac_bytes.at(1), mac_bytes.at(2), mac_bytes.at(3), mac_bytes.at(4), mac_bytes.at(5));

            if (written < 0 || static_cast<size_t>(written) >= mac_buf.size()) {
                return;
            }

            mac = mac_buf.data();
        }
    }
}

bool parse_netlink_message(struct nlmsghdr* hdr, std::vector<ArpEntry>& entries, int sock) {
    if (hdr->nlmsg_type == NLMSG_DONE) {
        close(sock);
        return false;  // Stop parsing loop
    }

    if (hdr->nlmsg_type == NLMSG_ERROR) {
        auto* err =
            reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(hdr));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        if (err->error != 0) {
            int const netlink_errno = -err->error;
            char const* err_str{nullptr};
            switch (netlink_errno) {
                case EACCES:
                    err_str = "Permission denied";
                    break;
                case EBADF:
                    err_str = "Bad file descriptor";
                    break;
                case EFAULT:
                    err_str = "Bad address";
                    break;
                case EINVAL:
                    err_str = "Invalid argument";
                    break;
                case ENOMEM:
                    err_str = "Out of memory";
                    break;
                case EPERM:
                    err_str = "Operation not permitted";
                    break;
                default:
                    err_str = "System error";
                    break;
            }
            int const written = std::fprintf(stderr, "Netlink error: errno=%d (%s)\n", netlink_errno, err_str);
            if (written < 0) {
                close(sock);
                return false;
            }
        }
        close(sock);
        return false;  // Stop parsing loop
    }

    if (hdr->nlmsg_type != RTM_NEWNEIGH) {
        return true;  // Continue loop
    }

    auto* ndm =
        reinterpret_cast<struct ndmsg*>(NLMSG_DATA(hdr));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    if (ndm->ndm_family != AF_INET) {
        return true;  // Continue loop
    }

    uint32_t ip_address{0};
    std::string mac{"00:00:00:00:00:00"};

    struct rtattr* rta = RTM_RTA(ndm);
    unsigned int const rta_len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm));

    parse_netlink_attributes(rta, rta_len, ip_address, mac);

    if (ip_address != 0) {
        // Skip entries still waiting for an ARP reply (Incomplete / Unresolved MAC)
        if ((ndm->ndm_state & NUD_INCOMPLETE) != 0 || mac == "00:00:00:00:00:00") {
            return true;
        }

        // Skip IPv4 multicast (224.0.0.0/4) and broadcast (255.255.255.255) ranges
        // NOLINTBEGIN(readability-magic-numbers)
        uint8_t const first_byte = (ip_address >> 24) & 0xFF;
        if ((first_byte >= 224 && first_byte <= 239) || ip_address == 0xFFFFFFFF) {
            return true;
        }
        // NOLINTEND(readability-magic-numbers)

        std::string ifname{"unknown"};
        std::array<char, IF_NAMESIZE> ifname_buf{};

        if (if_indextoname(static_cast<unsigned int>(ndm->ndm_ifindex), ifname_buf.data()) != nullptr) {
            ifname = ifname_buf.data();
        }

        entries.push_back({ip_address, mac, ndm->ndm_ifindex, ifname});
    }

    return true;
}

std::vector<ArpEntry> get_arp_table() {
    std::vector<ArpEntry> entries;

    int const sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        return entries;
    }

    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
    } req{};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.ndm.ndm_family = AF_INET;

    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(sock);
        return entries;
    }

    constexpr size_t rx_buf_size = 65536;
    std::vector<uint8_t> buf(rx_buf_size);

    for (;;) {
        struct iovec iov{};  // NOLINT(misc-include-cleaner)
        iov.iov_base = buf.data();
        iov.iov_len = buf.size();

        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t const len = recvmsg(sock, &msg, 0);

        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if ((static_cast<unsigned int>(msg.msg_flags) & MSG_TRUNC) != 0) {
            int const written = std::fprintf(stderr, "Netlink response was truncated\n");
            if (written < 0) {
                close(sock);
                return entries;
            }
            break;
        }

        unsigned int remaining = static_cast<unsigned int>(len);
        bool continue_loop = true;

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        for (struct nlmsghdr* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data()); NLMSG_OK(hdr, remaining);
             hdr = NLMSG_NEXT(hdr, remaining)) {
            if (!parse_netlink_message(hdr, entries, sock)) {
                continue_loop = false;
                break;
            }
        }

        if (!continue_loop) {
            return entries;
        }
    }

    close(sock);
    return entries;
}

void print_arp_table(bool resolve_dns) {
    auto arp_entries = get_arp_table();

    if (arp_entries.empty()) {
        std::printf("[*] No ARP entries found in kernel cache.\n");
        return;
    }

    std::printf("%-15s | %-17s | %-10s | %-30s\n", "IP ADDRESS", "MAC ADDRESS", "INTERFACE", "HOSTNAME");
    std::printf("------------------------------------------------------------------------------------\n");

    std::array<char, INET_ADDRSTRLEN> ip_str{};

    for (auto const& entry : arp_entries) {
        format_ip(entry.ip, ip_str.data(), ip_str.size());

        std::string hostname{"N/A"};
        if (resolve_dns) {
            hostname = resolve_hostname(entry.ip);
        }

        std::printf("%-15s | %-17s | %-10s | %-30s\n", ip_str.data(), entry.mac_address.c_str(),
                    entry.iface_name.c_str(), hostname.c_str());
    }
    std::printf("------------------------------------------------------------------------------------\n");
    std::printf("[+] Total cached ARP entries: %zu\n", arp_entries.size());
}

}  // namespace netscan
