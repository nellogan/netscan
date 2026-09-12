#include "tcp_scanner.hpp"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>  // NOLINT(modernize-deprecated-headers)
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <system_error>
#include <vector>

#include "utils.hpp"

namespace netscan {

TcpScanner::TcpScanner(TcpScannerConfig const& config)
    : base_ip_(config.base_ip),
      total_hosts_(config.total_hosts),
      network_interface_(NetworkInterface::fetch(config.base_ip, static_cast<uint32_t>(config.total_hosts))),
      target_port_(config.target_port),
      max_probes_(std::min(config.max_probes, config.total_hosts)),
      timeout_ms_(config.timeout_ms),
      batch_size_(safe_batch_size(config.batch_size, config.total_hosts)),
      resolve_dns_(config.resolve_dns),
      result_callback_(config.result_callback),
      probe_table_(max_probes_),
      epoll_fd_(epoll_create1(EPOLL_CLOEXEC)) {
    if (epoll_fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_create1");
    }
}

TcpScanner::~TcpScanner() {
    for (auto& probe : probe_table_) {
        if (probe.active && probe.sock >= 0) {
            close(probe.sock);
        }
    }
    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
    }
}

std::vector<TcpHostResult> TcpScanner::run() {
    size_t next_host_idx{0};
    size_t active_probes{0};
    size_t hosts_found{0};
    std::vector<TcpHostResult> scan_results;

    while (next_host_idx < total_hosts_ || active_probes > 0) {
        initiate_connections(next_host_idx, active_probes);
        poll_connections(active_probes, hosts_found, scan_results);
        reap_timed_out_probes(active_probes);
    }

    return scan_results;
}

bool TcpScanner::initiate_single_connection(size_t& next_host_idx, size_t& active_probes) {
    uint32_t const target_ip = base_ip_ + static_cast<uint32_t>(next_host_idx);

    // Skip true local subnet network ID and broadcast address
    if (network_interface_.is_local &&
        (target_ip == network_interface_.network_ip || target_ip == network_interface_.broadcast_ip)) {
        next_host_idx++;
        return true;
    }

    int slot{-1};
    for (size_t i = 0; i < probe_table_.size(); i++) {
        if (!probe_table_[i].active) {
            slot = static_cast<int>(i);
            break;
        }
    }
    if (slot == -1) {
        return false;
    }

    next_host_idx++;

    int const sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return true;
    }

    constexpr int tcp_buffer_scale_factor = 1024;
    int tcp_buf_size = static_cast<int>(max_probes_) * tcp_buffer_scale_factor;

    // NOLINTBEGIN(misc-include-cleaner)
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &tcp_buf_size, sizeof(tcp_buf_size)) < 0) {
        perror("setsockopt(SO_SNDBUF)");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &tcp_buf_size, sizeof(tcp_buf_size)) < 0) {
        perror("setsockopt(SO_RCVBUF)");
    }
    // NOLINTEND(misc-include-cleaner)

    int const flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, static_cast<unsigned int>(flags) | O_NONBLOCK) < 0) {
        close(sock);
        return true;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port_);
    addr.sin_addr.s_addr = htonl(target_ip);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    int const res = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (res < 0 && errno != EINPROGRESS) {
        close(sock);
        return true;
    }

    epoll_event event{};
    event.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
    assert(slot >= 0);
    event.data.u32 = static_cast<uint32_t>(slot);

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, sock, &event) < 0) {
        close(sock);
        return true;
    }

    timespec now{};
    clock_gettime(CLOCK_REALTIME, &now);  // NOLINT(misc-include-cleaner)

    probe_table_[static_cast<size_t>(slot)] = {true, sock, target_ip, now};
    active_probes++;
    return true;
}

void TcpScanner::initiate_connections(size_t& next_host_idx, size_t& active_probes) {
    size_t initiated{0};
    while (next_host_idx < total_hosts_ && active_probes < max_probes_ && initiated < batch_size_) {
        size_t const before = next_host_idx;
        if (!initiate_single_connection(next_host_idx, active_probes)) {
            break;
        }
        if (next_host_idx > before) {
            initiated++;
        }
    }
}

void TcpScanner::poll_connections(size_t& active_probes, size_t& hosts_found,
                                  std::vector<TcpHostResult>& scan_results) {
    int const max_events = static_cast<int>(batch_size_);
    std::vector<epoll_event> events(static_cast<size_t>(max_events));

    int const event_count = epoll_wait(epoll_fd_, events.data(), max_events, EPOLL_TIMEOUT_MS);

    std::array<char, INET_ADDRSTRLEN> ip_str{};

    for (int i = 0; i < event_count; i++) {
        uint32_t const raw_slot = events[static_cast<size_t>(i)].data.u32;
        if (raw_slot >= probe_table_.size()) {
            continue;
        }

        size_t const slot = static_cast<size_t>(raw_slot);
        if (!probe_table_[slot].active) {
            continue;
        }

        auto& probe = probe_table_[slot];
        int const sock = probe.sock;

        int sock_err = 0;
        socklen_t len = sizeof(sock_err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_err, &len) < 0) {  // NOLINT(misc-include-cleaner)
            sock_err = errno;
        }

        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, sock, nullptr);
        close(sock);
        probe.active = false;
        active_probes--;

        timespec now{};
        clock_gettime(CLOCK_REALTIME, &now);
        int64_t const diff_ns = ((now.tv_sec - probe.send_time.tv_sec) * NANOSECONDS_PER_SECOND_LL) +
                                (now.tv_nsec - probe.send_time.tv_nsec);

        double const rtt_ms = std::max(0.0, static_cast<double>(diff_ns) / NANOSECONDS_PER_MILLISECOND_D);

        if (sock_err == 0) {
            format_ip(probe.dest_ip, ip_str.data(), ip_str.size());

            std::string hostname{"N/A"};
            if (resolve_dns_) {
                hostname = netscan::resolve_hostname(probe.dest_ip);
            }

            TcpHostResult const result{probe.dest_ip, std::string(ip_str.data()), hostname, target_port_, rtt_ms};

            if (result_callback_) {
                result_callback_(result);
            }

            if (std::find_if(scan_results.begin(), scan_results.end(),
                             [ip_address = probe.dest_ip](TcpHostResult const& result) {
                                 return result.ip == ip_address;
                             }) == scan_results.end()) {
                scan_results.push_back(result);
                hosts_found++;
            }
        }
    }
}

void TcpScanner::reap_timed_out_probes(size_t& active_probes) {
    timespec current_time{};
    clock_gettime(CLOCK_REALTIME, &current_time);

    for (auto& probe : probe_table_) {
        if (probe.active) {
            int64_t const elapsed_ns = ((current_time.tv_sec - probe.send_time.tv_sec) * NANOSECONDS_PER_SECOND_LL) +
                                       (current_time.tv_nsec - probe.send_time.tv_nsec);
            if (elapsed_ns > (timeout_ms_ * NANOSECONDS_PER_MILLISECOND_LL)) {
                epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, probe.sock, nullptr);
                close(probe.sock);
                probe.active = false;
                active_probes--;
            }
        }
    }
}

}  // namespace netscan