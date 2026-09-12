#ifndef TCP_SCANNER_HPP
#define TCP_SCANNER_HPP

#include <time.h>  // NOLINT(modernize-deprecated-headers)

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "utils.hpp"

namespace netscan {

struct TcpHostResult {
    uint32_t ip;
    std::string ip_str;
    std::string hostname;
    uint16_t port;
    double rtt_ms;
};

using TcpScanCallback = std::function<void(TcpHostResult const&)>;

struct TcpScannerConfig {
    uint32_t base_ip{0};
    size_t total_hosts{0};
    uint16_t target_port{DEFAULT_TCP_PORT};
    size_t max_probes{DEFAULT_MAX_PROBES};
    uint32_t timeout_ms{DEFAULT_TCP_TIMEOUT_MS};
    size_t batch_size{DEFAULT_TCP_BATCH_SIZE};
    bool resolve_dns{DEFAULT_RESOLVE_DNS};
    TcpScanCallback result_callback{nullptr};
};

class TcpScanner {
   public:
    explicit TcpScanner(TcpScannerConfig const& config);

    ~TcpScanner();

    TcpScanner(TcpScanner const&) = delete;
    TcpScanner& operator=(TcpScanner const&) = delete;
    TcpScanner(TcpScanner&&) = delete;
    TcpScanner& operator=(TcpScanner&&) = delete;

    std::vector<TcpHostResult> run();

   private:
    struct ProbeInfo {
        bool active{false};
        int sock{-1};
        uint32_t dest_ip{0};
        timespec send_time{0, 0};
    };

    uint32_t base_ip_{0};
    size_t total_hosts_{0};
    NetworkInterface network_interface_{};

    uint16_t target_port_{0};

    size_t max_probes_{0};
    uint32_t timeout_ms_{0};

    size_t batch_size_{0};

    bool resolve_dns_{false};

    TcpScanCallback result_callback_;

    std::vector<ProbeInfo> probe_table_;

    int epoll_fd_{-1};

    bool initiate_single_connection(size_t& next_host_idx, size_t& active_probes);

    void initiate_connections(size_t& next_host_idx, size_t& active_probes);

    void poll_connections(size_t& active_probes, size_t& hosts_found, std::vector<TcpHostResult>& scan_results);

    void reap_timed_out_probes(size_t& active_probes);
};

}  // namespace netscan

#endif  // TCP_SCANNER_HPP