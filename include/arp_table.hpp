#ifndef ARP_TABLE_HPP
#define ARP_TABLE_HPP

#include <linux/netlink.h>    // struct nlmsghdr
#include <linux/rtnetlink.h>  // struct rtattr

#include <cstdint>
#include <string>
#include <vector>

namespace netscan {

struct ArpEntry {
    uint32_t ip{0};
    std::string mac_address;
    int interface_index{0};
    std::string iface_name;  // Human-readable name (e.g., "eth0", "wlan0")
};

// Parse individual routing attributes (NDA_DST, NDA_LLADDR)
void parse_netlink_attributes(struct rtattr* rta, unsigned int rta_len, uint32_t& ip_address, std::string& mac);

// Parse a single Netlink message header
bool parse_netlink_message(struct nlmsghdr* hdr, std::vector<ArpEntry>& entries, int sock);

std::vector<ArpEntry> get_arp_table();

void print_arp_table(bool resolve_dns = true);

}  // namespace netscan

#endif  // ARP_TABLE_HPP