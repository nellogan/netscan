#ifndef PING_SCANNER_HPP
#define PING_SCANNER_HPP

#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>  // NOLINT(modernize-deprecated-headers)

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "utils.hpp"

namespace netscan {

struct PingHostResult {
    uint32_t ip;
    std::string ip_str;
    std::string hostname;
    double rtt_ms;
    int ttl;
};

struct PingScanResult {
    std::vector<PingHostResult> hosts;
    uint32_t tx_drops{0};
    uint32_t rx_queue_overflows{0};
    uint32_t echo_replies{0};
    uint32_t unmatched_replies{0};
    uint32_t probe_timeouts{0};
};

using PingScanCallback = std::function<void(PingHostResult const&)>;

struct PingScannerConfig {
    uint32_t base_ip{0};
    size_t total_hosts{0};
    size_t payload_len{DEFAULT_PAYLOAD_LEN};
    size_t max_probes{DEFAULT_MAX_PROBES};
    uint32_t timeout_ms{DEFAULT_PING_TIMEOUT_MS};
    size_t send_batch_size{DEFAULT_PING_SEND_BATCH_SIZE};
    size_t recv_batch_size{DEFAULT_PING_RECV_BATCH_SIZE};
    bool resolve_dns{DEFAULT_RESOLVE_DNS};
    PingScanCallback result_callback{nullptr};
};

class PingScanner {
   public:
    explicit PingScanner(PingScannerConfig const& config);

    ~PingScanner();

    PingScanner(PingScanner const&) = delete;
    PingScanner& operator=(PingScanner const&) = delete;
    PingScanner(PingScanner&&) = delete;
    PingScanner& operator=(PingScanner&&) = delete;

    PingScanResult run();

   private:
    // CMSG_SPACE (from <sys/socket.h>) calculates the total buffer bytes required
    // for an ancillary control message, including its header, payload, and alignment padding.
    static constexpr size_t CONTROL_BUFFER_SIZE = CMSG_SPACE(sizeof(int)) +       // For IP_TTL
                                                  CMSG_SPACE(sizeof(timespec)) +  // For SO_TIMESTAMPNS
                                                  CMSG_SPACE(sizeof(uint32_t));   // For SO_RXQ_OVFL

    struct IcmpHdr {
        uint8_t type{0};
        uint8_t code{0};
        uint16_t checksum{0};
        uint16_t id{0};
        uint16_t sequence{0};
    };

    struct PingPayload {
        uint32_t target_ip{0};
        int64_t send_sec{0};
        int64_t send_nsec{0};
    };

    struct ProbeInfo {
        bool active{false};
        uint32_t dest_ip{0};
        uint16_t seq{0};
        timespec send_time{0, 0};
    };

    uint32_t base_ip_{0};
    size_t total_hosts_{0};
    NetworkInterface network_interface_{};

    size_t payload_len_{0};

    size_t max_probes_{0};
    uint32_t timeout_ms_{0};

    size_t send_batch_size_{0};
    size_t recv_batch_size_{0};

    bool resolve_dns_{false};

    PingScanCallback result_callback_;

    int sock_{-1};

    int epoll_fd_{-1};

    size_t packet_buffer_size_{0};

    uint32_t tx_drops_{0};
    uint32_t rx_queue_overflows_{0};
    uint32_t echo_replies_{0};
    uint32_t unmatched_replies_{0};
    uint32_t probe_timeouts_{0};

    std::vector<ProbeInfo> probe_table_;
    std::vector<int> host_to_probe_;
    std::vector<uint32_t> found_ips_cache_;

    std::vector<uint8_t> send_packets_;
    std::vector<sockaddr_in> send_addrs_;
    std::vector<iovec> send_iovs_;  // NOLINT(misc-include-cleaner)
    std::vector<mmsghdr> send_msgvec_;
    std::vector<int> send_probe_slots_;

    std::vector<mmsghdr> rx_msgvec_;
    std::vector<iovec> rx_iovs_;
    std::vector<sockaddr_in> rx_addrs_;
    std::vector<uint8_t> rx_storage_;
    std::vector<uint8_t> rx_controls_;

    void initialize_buffers();

    void initialize_socket();

    [[nodiscard]] bool wait_for_socket_writable() const;

    [[nodiscard]] int find_available_probe_slot() const;

    [[nodiscard]] int host_index_for_ip(uint32_t ip_address) const;

    [[nodiscard]] bool is_host_found(uint32_t ip_address) const;

    [[nodiscard]] static uint16_t allocate_sequence(uint16_t& next_seq);

    void release_probe_slot(int slot, size_t& active_probes);

    void extract_control_data(int msg_index, int& ttl, timespec& recv_ts, bool& has_recv_ts);

    void prepare_single_packet(size_t batch_count, uint32_t target_ip_host, uint16_t sequence, timespec const& send_ts);

    bool populate_batch_entries(size_t& next_host_idx, size_t& active_probes, uint16_t& next_seq, size_t& batch_count,
                                timespec const& send_ts);

    bool flush_send_queue(size_t batch_count, size_t& active_probes, size_t& next_host_idx);

    bool send_batch(size_t& next_host_idx, size_t& active_probes, uint16_t& next_seq);

    void process_received_packet(int msg_index, timespec const& recv_ts, int ttl, size_t& active_probes,
                                 size_t& hosts_found, std::vector<PingHostResult>& scan_results);

    void receive_responses(size_t& active_probes, size_t& hosts_found, std::vector<PingHostResult>& scan_results,
                           bool blocking = true);

    void reap_timed_out_probes(size_t& active_probes);
};

}  // namespace netscan

#endif  // PING_SCANNER_HPP