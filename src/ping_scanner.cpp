#include "ping_scanner.hpp"

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "utils.hpp"

namespace netscan {

PingScanner::PingScanner(PingScannerConfig const& config)
    : base_ip_(config.base_ip),
      total_hosts_(config.total_hosts),
      network_interface_(NetworkInterface::fetch(config.base_ip, static_cast<uint32_t>(config.total_hosts))),
      payload_len_(config.payload_len),
      max_probes_(std::min(config.max_probes, config.total_hosts)),
      timeout_ms_(config.timeout_ms),
      send_batch_size_(safe_batch_size(config.send_batch_size, config.total_hosts)),
      recv_batch_size_(safe_batch_size(config.recv_batch_size, config.total_hosts)),
      resolve_dns_(config.resolve_dns),
      result_callback_(config.result_callback),
      packet_buffer_size_(sizeof(IcmpHdr) + sizeof(PingPayload) + payload_len_),
      probe_table_(max_probes_),
      host_to_probe_(total_hosts_, -1) {
    initialize_buffers();
    initialize_socket();
}

PingScanner::~PingScanner() {
    if (sock_ >= 0) {
        close(sock_);
    }

    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
    }
}

PingScanResult PingScanner::run() {
    std::fill(probe_table_.begin(), probe_table_.end(), ProbeInfo{});
    std::fill(host_to_probe_.begin(), host_to_probe_.end(), -1);
    found_ips_cache_.clear();

    tx_drops_ = 0;
    rx_queue_overflows_ = 0;
    echo_replies_ = 0;
    unmatched_replies_ = 0;
    probe_timeouts_ = 0;

    size_t next_host_idx{0};
    size_t active_probes{0};
    size_t hosts_found{0};
    uint16_t next_seq{1};
    std::vector<PingHostResult> scan_results;

    while (next_host_idx < total_hosts_ || active_probes > 0) {
        if (!send_batch(next_host_idx, active_probes, next_seq)) {
            break;
        }

        receive_responses(active_probes, hosts_found, scan_results, true);
        reap_timed_out_probes(active_probes);
    }

    return PingScanResult{
        std::move(scan_results), tx_drops_, rx_queue_overflows_, echo_replies_, unmatched_replies_, probe_timeouts_,
    };
}

void PingScanner::initialize_buffers() {
    size_t const send_count = std::max<size_t>(1, send_batch_size_);
    size_t const recv_count = std::max<size_t>(1, recv_batch_size_);

    send_packets_.resize(packet_buffer_size_ * send_count);
    send_addrs_.resize(send_count);
    send_iovs_.resize(send_count);
    send_msgvec_.resize(send_count);
    send_probe_slots_.assign(send_count, -1);

    rx_msgvec_.resize(recv_count);
    rx_iovs_.resize(recv_count);
    rx_addrs_.resize(recv_count);
    rx_storage_.resize(recv_count * MAX_RX_PACKET_SIZE);
    rx_controls_.resize(recv_count * CONTROL_BUFFER_SIZE);
}

void PingScanner::initialize_socket() {
    sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock_ < 0) {
        throw std::system_error(errno, std::generic_category(), "socket(SOCK_DGRAM, IPPROTO_ICMP)");
    }

    int const flags = fcntl(sock_, F_GETFL, 0);
    if (flags < 0) {
        int const error{errno};
        close(sock_);
        sock_ = -1;
        throw std::system_error(error, std::generic_category(), "fcntl(F_GETFL)");
    }

    uint32_t const new_flags = static_cast<uint32_t>(flags) | static_cast<uint32_t>(O_NONBLOCK);
    if (fcntl(sock_, F_SETFL, static_cast<int>(new_flags)) < 0) {
        int const error{errno};
        close(sock_);
        sock_ = -1;
        throw std::system_error(error, std::generic_category(), "fcntl(F_SETFL)");
    }

    size_t const buffer_probe_count = std::max<size_t>(1, max_probes_);
    int send_buf_size = static_cast<int>(MAX_RX_PACKET_SIZE * buffer_probe_count);
    int recv_buf_size = static_cast<int>(MAX_RX_PACKET_SIZE * buffer_probe_count);

    // NOLINTBEGIN(misc-include-cleaner)
    if (setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, &send_buf_size, sizeof(send_buf_size)) < 0) {
        int const error{errno};
        close(sock_);
        sock_ = -1;
        throw std::system_error(error, std::generic_category(), "setsockopt(SO_SNDBUF)");
    }

    if (setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, sizeof(recv_buf_size)) < 0) {
        int const error{errno};
        close(sock_);
        sock_ = -1;
        throw std::system_error(error, std::generic_category(), "setsockopt(SO_RCVBUF)");
    }

    int enable{1};
    if (setsockopt(sock_, SOL_SOCKET, SO_TIMESTAMPNS, &enable, sizeof(enable)) < 0) {
        int const error{errno};
        // SO_TIMESTAMPNS is optional. If the kernel or emulation layer (like ARM64 QEMU)
        // doesn't support it, fall back gracefully rather than hard-crashing.
        if (error != ENOPROTOOPT && error != EINVAL) {
            close(sock_);
            sock_ = -1;
            throw std::system_error(error, std::generic_category(), "setsockopt(SO_TIMESTAMPNS)");
        }
    }

    if (setsockopt(sock_, SOL_SOCKET, SO_RXQ_OVFL, &enable, sizeof(enable)) < 0) {
        int const error{errno};
        // SO_RXQ_OVFL is optional. If unsupported by the kernel or emulation layer
        // (like ARM64 QEMU), skip it without throwing an unhandled exception.
        if (error != ENOPROTOOPT && error != EINVAL) {
            close(sock_);
            sock_ = -1;
            throw std::system_error(error, std::generic_category(), "setsockopt(SO_RXQ_OVFL)");
        }
    }

    if (setsockopt(sock_, IPPROTO_IP, IP_RECVTTL, &enable, sizeof(enable)) < 0) {
        int const error{errno};
        close(sock_);
        sock_ = -1;
        throw std::system_error(error, std::generic_category(), "setsockopt(IP_RECVTTL)");
    }

    // NetworkInterface::fetch() identifies when the target range overlaps
    // the local interface's subnet. populate_batch_entries() skips the
    // local network and broadcast addresses in that case, so SO_BROADCAST
    // is not required here.
    //    if (setsockopt(sock_, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0) {
    //        int error{errno};
    //        close(sock_);
    //        sock_ = -1;
    //        throw std::system_error(error, std::generic_category(), "setsockopt(SO_BROADCAST)");
    //    }

    // NOLINTEND(misc-include-cleaner)

    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        int const error{errno};
        close(sock_);
        sock_ = -1;
        throw std::system_error(error, std::generic_category(), "epoll_create1");
    }

    epoll_event event{};
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = sock_;

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, sock_, &event) < 0) {
        int const error{errno};
        close(epoll_fd_);
        epoll_fd_ = -1;
        close(sock_);
        sock_ = -1;
        throw std::system_error(error, std::generic_category(), "epoll_ctl(EPOLL_CTL_ADD)");
    }
}

bool PingScanner::wait_for_socket_writable() const {
    epoll_event event{};
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.fd = sock_;

    int const timeout_ms = static_cast<int>(timeout_ms_);

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, sock_, &event) < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_ctl(EPOLLOUT)");
    }

    bool writable{false};

    for (;;) {
        int const event_count = epoll_wait(epoll_fd_, &event, 1, timeout_ms);

        if (event_count < 0) {
            if (errno == EINTR) {
                continue;
            }

            throw std::system_error(errno, std::generic_category(), "epoll_wait(EPOLLOUT)");
        }

        if (event_count == 0) {
            // Normal timeout: the socket did not become writable.
            break;
        }

        if ((event.events & EPOLLOUT) != 0U) {
            writable = true;
            break;
        }

        if ((event.events & (EPOLLERR | EPOLLHUP)) != 0U) {
            // epoll reported a socket error/closure rather than writability.
            break;
        }
    }

    event = {};
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = sock_;

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, sock_, &event) < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_ctl(EPOLLIN)");
    }

    return writable;
}

int PingScanner::find_available_probe_slot() const {
    for (size_t i = 0; i < probe_table_.size(); ++i) {
        if (!probe_table_[i].active) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int PingScanner::host_index_for_ip(uint32_t ip_address) const {
    if (ip_address < base_ip_) {
        return -1;
    }
    uint32_t const index = ip_address - base_ip_;
    if (index >= total_hosts_) {
        return -1;
    }
    return static_cast<int>(index);
}

bool PingScanner::is_host_found(uint32_t ip_address) const {
    return std::find(found_ips_cache_.begin(), found_ips_cache_.end(), ip_address) != found_ips_cache_.end();
}

uint16_t PingScanner::allocate_sequence(uint16_t& next_seq) {
    uint16_t candidate{next_seq};
    if (candidate == 0) {
        candidate = 1;
    }
    next_seq = static_cast<uint16_t>(candidate + 1);
    if (next_seq == 0) {
        next_seq = 1;
    }
    return candidate;
}

void PingScanner::release_probe_slot(int slot, size_t& active_probes) {
    if (slot < 0 || static_cast<size_t>(slot) >= probe_table_.size()) {
        return;
    }

    ProbeInfo& probe = probe_table_[static_cast<size_t>(slot)];
    if (!probe.active) {
        return;
    }

    int const host_idx = host_index_for_ip(probe.dest_ip);
    if (host_idx >= 0 && host_to_probe_[static_cast<size_t>(host_idx)] == slot) {
        host_to_probe_[static_cast<size_t>(host_idx)] = -1;
    }

    probe.active = false;
    if (active_probes > 0) {
        --active_probes;
    }
}

void PingScanner::extract_control_data(int msg_index, int& ttl, timespec& recv_ts, bool& has_recv_ts) {
    msghdr& hdr = rx_msgvec_[static_cast<size_t>(msg_index)].msg_hdr;

    for (cmsghdr* cmsg = CMSG_FIRSTHDR(&hdr); cmsg != nullptr; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) {
            std::memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
        }

        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPNS) {
            std::memcpy(&recv_ts, CMSG_DATA(cmsg), sizeof(timespec));
            has_recv_ts = true;
        }

        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
            uint32_t drops{0};
            std::memcpy(&drops, CMSG_DATA(cmsg), sizeof(drops));
            rx_queue_overflows_ = std::max(drops, rx_queue_overflows_);
        }
    }

    if (!has_recv_ts) {
        clock_gettime(CLOCK_REALTIME, &recv_ts);  // NOLINT(misc-include-cleaner)
    }
}

void PingScanner::prepare_single_packet(size_t batch_count, uint32_t target_ip, uint16_t sequence,
                                        timespec const& send_ts) {
    constexpr uint16_t pid_mask_16_bit{0xFFFF};
    uint16_t const pid16 = static_cast<uint16_t>(static_cast<uint32_t>(getpid()) & pid_mask_16_bit);

    size_t const packet_offset = batch_count * packet_buffer_size_;

    IcmpHdr icmp{};
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.checksum = 0;
    icmp.id = htons(pid16);
    icmp.sequence = htons(sequence);
    std::memcpy(&send_packets_[packet_offset], &icmp, sizeof(IcmpHdr));

    PingPayload payload_data{};
    payload_data.target_ip = target_ip;
    payload_data.send_sec = send_ts.tv_sec;
    payload_data.send_nsec = send_ts.tv_nsec;
    std::memcpy(&send_packets_[packet_offset + sizeof(IcmpHdr)], &payload_data, sizeof(PingPayload));

    // Append extra padding bytes immediately after PingPayload if configured
    if (payload_len_ > 0) {
        size_t const extra_offset = packet_offset + sizeof(IcmpHdr) + sizeof(PingPayload);
        for (size_t i = 0; i < payload_len_; ++i) {
            send_packets_[extra_offset + i] = static_cast<uint8_t>((i + PAYLOAD_CHAR_MOD) % PAYLOAD_CHAR_OFFSET);
        }
    }

    std::memset(&send_addrs_[batch_count], 0, sizeof(sockaddr_in));
    send_addrs_[batch_count].sin_family = AF_INET;
    send_addrs_[batch_count].sin_addr.s_addr = htonl(target_ip);

    send_iovs_[batch_count].iov_base = &send_packets_[packet_offset];
    send_iovs_[batch_count].iov_len = packet_buffer_size_;

    std::memset(&send_msgvec_[batch_count], 0, sizeof(mmsghdr));
    send_msgvec_[batch_count].msg_hdr.msg_name = &send_addrs_[batch_count];
    send_msgvec_[batch_count].msg_hdr.msg_namelen = sizeof(sockaddr_in);
    send_msgvec_[batch_count].msg_hdr.msg_iov = &send_iovs_[batch_count];
    send_msgvec_[batch_count].msg_hdr.msg_iovlen = 1;
}

bool PingScanner::populate_batch_entries(size_t& next_host_idx, size_t& active_probes, uint16_t& next_seq,
                                         size_t& batch_count, timespec const& send_ts) {
    while (next_host_idx < total_hosts_ && active_probes < max_probes_ && batch_count < send_batch_size_) {
        if (find_available_probe_slot() < 0) {
            break;
        }

        uint32_t const target_ip = base_ip_ + static_cast<uint32_t>(next_host_idx);

        if (network_interface_.is_local &&
            (target_ip == network_interface_.network_ip || target_ip == network_interface_.broadcast_ip)) {
            ++next_host_idx;
            continue;
        }

        int const host_idx = host_index_for_ip(target_ip);
        if (host_idx < 0 || is_host_found(target_ip) || host_to_probe_[static_cast<size_t>(host_idx)] >= 0) {
            ++next_host_idx;
            continue;
        }

        int const slot = find_available_probe_slot();
        if (slot < 0) {
            break;
        }

        uint16_t const candidate = allocate_sequence(next_seq);

        ProbeInfo& probe = probe_table_[static_cast<size_t>(slot)];
        probe.active = true;
        probe.dest_ip = target_ip;
        probe.seq = candidate;
        probe.send_time = send_ts;

        host_to_probe_[static_cast<size_t>(host_idx)] = slot;

        prepare_single_packet(batch_count, target_ip, candidate, send_ts);
        send_probe_slots_[batch_count] = slot;

        ++batch_count;
        ++next_host_idx;
        ++active_probes;
    }
    return batch_count > 0;
}

bool PingScanner::flush_send_queue(size_t batch_count, size_t& active_probes, size_t& next_host_idx) {
    size_t sent_total{0};

    while (sent_total < batch_count) {
        errno = 0;
        size_t const remaining = batch_count - sent_total;

        int const sent = sendmmsg(sock_, &send_msgvec_[sent_total], static_cast<unsigned int>(remaining), 0);

        if (sent > 0) {
            sent_total += static_cast<size_t>(sent);
            continue;
        }

        int const send_errno{errno};

        if (send_errno == EAGAIN || send_errno == EWOULDBLOCK) {
            ++tx_drops_;

            if (!wait_for_socket_writable()) {
                for (size_t i = sent_total; i < batch_count; ++i) {
                    release_probe_slot(send_probe_slots_[i], active_probes);
                    send_probe_slots_[i] = -1;
                }

                next_host_idx -= batch_count - sent_total;
                return false;
            }

            continue;
        }

        char const* err_str{nullptr};
        switch (send_errno) {
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
            case ENOTSOCK:
                err_str = "Socket operation on non-socket";
                break;
            case EMSGSIZE:
                err_str = "Message too long";
                break;
            case ENOBUFS:
                err_str = "No buffer space available";
                break;
            default:
                err_str = "System error";
                break;
        }
        (void)std::fprintf(stderr, "sendmmsg: errno=%d (%s)\n", send_errno, err_str);

        for (size_t i = sent_total; i < batch_count; ++i) {
            release_probe_slot(send_probe_slots_[i], active_probes);
            send_probe_slots_[i] = -1;
        }

        next_host_idx -= batch_count - sent_total;

        errno = send_errno;
        return false;
    }

    for (size_t i = 0; i < batch_count; ++i) {
        send_probe_slots_[i] = -1;
    }

    return true;
}

bool PingScanner::send_batch(size_t& next_host_idx, size_t& active_probes, uint16_t& next_seq) {
    size_t batch_count{0};

    timespec send_ts{};
    clock_gettime(CLOCK_REALTIME, &send_ts);

    if (!populate_batch_entries(next_host_idx, active_probes, next_seq, batch_count, send_ts)) {
        if (batch_count == 0) {
            return true;
        }
    }

    if (batch_count == 0) {
        return true;
    }

    return flush_send_queue(batch_count, active_probes, next_host_idx);
}

void PingScanner::process_received_packet(int msg_index, timespec const& recv_ts, int ttl, size_t& active_probes,
                                          size_t& hosts_found, std::vector<PingHostResult>& scan_results) {
    std::array<char, INET_ADDRSTRLEN> src_str{};
    size_t const idx = static_cast<size_t>(msg_index);
    size_t const packet_offset = idx * MAX_RX_PACKET_SIZE;

    ssize_t const packet_len = rx_msgvec_[idx].msg_len;
    if (packet_len < static_cast<ssize_t>(sizeof(IcmpHdr) + sizeof(PingPayload))) {
        ++unmatched_replies_;
        return;
    }

    IcmpHdr recved_icmp{};
    std::memcpy(&recved_icmp, &rx_storage_[packet_offset], sizeof(IcmpHdr));

    if (recved_icmp.type != ICMP_ECHOREPLY) {
        return;
    }

    ++echo_replies_;

    uint32_t const actual_src_ip = ntohl(rx_addrs_[idx].sin_addr.s_addr);

    PingPayload payload_data{};
    std::memcpy(&payload_data, &rx_storage_[packet_offset + sizeof(IcmpHdr)], sizeof(PingPayload));

    if (actual_src_ip != payload_data.target_ip) {
        ++unmatched_replies_;
        return;
    }

    int const host_idx = host_index_for_ip(payload_data.target_ip);
    if (host_idx < 0) {
        ++unmatched_replies_;
        return;
    }

    // If we already recorded this host as found, ignore duplicate late replies
    if (is_host_found(payload_data.target_ip)) {
        ++unmatched_replies_;
        return;
    }

    // Instead of failing if the slot was reaped, compute RTT directly from the payload timestamp
    int64_t const diff_ns = ((recv_ts.tv_sec - payload_data.send_sec) * NANOSECONDS_PER_SECOND_LL) +
                            (recv_ts.tv_nsec - payload_data.send_nsec);

    double const rtt_ms = std::max(0.0, static_cast<double>(diff_ns) / NANOSECONDS_PER_MILLISECOND_D);

    found_ips_cache_.push_back(payload_data.target_ip);
    ++hosts_found;

    // Clean up active slot if it was still holding this host
    int const slot = host_to_probe_[static_cast<size_t>(host_idx)];
    if (slot >= 0 && static_cast<size_t>(slot) < probe_table_.size()) {
        ProbeInfo& probe = probe_table_[static_cast<size_t>(slot)];
        if (probe.active && probe.dest_ip == payload_data.target_ip) {
            probe.active = false;
            if (active_probes > 0) {
                --active_probes;
            }
        }
        host_to_probe_[static_cast<size_t>(host_idx)] = -1;
    }

    format_ip(payload_data.target_ip, src_str.data(), src_str.size());

    std::string hostname{"N/A"};
    if (resolve_dns_) {
        hostname = netscan::resolve_hostname(payload_data.target_ip);
    }

    PingHostResult const result{payload_data.target_ip, std::string(src_str.data()), hostname, rtt_ms, ttl};

    if (result_callback_) {
        result_callback_(result);
    }

    scan_results.push_back(result);
}

void PingScanner::receive_responses(size_t& active_probes, size_t& hosts_found,
                                    std::vector<PingHostResult>& scan_results, bool blocking) {
    if (blocking) {
        epoll_event active_event{};
        int const sel = epoll_wait(epoll_fd_, &active_event, 1, EPOLL_TIMEOUT_MS);
        if (sel <= 0 || (active_event.events & EPOLLIN) == 0U) {
            return;
        }
    }

    for (;;) {
        std::memset(rx_msgvec_.data(), 0, rx_msgvec_.size() * sizeof(mmsghdr));

        for (size_t i = 0; i < recv_batch_size_; ++i) {
            std::memset(&rx_addrs_[i], 0, sizeof(sockaddr_in));
            std::memset(&rx_controls_[i * CONTROL_BUFFER_SIZE], 0, CONTROL_BUFFER_SIZE);

            rx_iovs_[i].iov_base = &rx_storage_[i * MAX_RX_PACKET_SIZE];
            rx_iovs_[i].iov_len = MAX_RX_PACKET_SIZE;

            rx_msgvec_[i].msg_hdr.msg_name = &rx_addrs_[i];
            rx_msgvec_[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
            rx_msgvec_[i].msg_hdr.msg_iov = &rx_iovs_[i];
            rx_msgvec_[i].msg_hdr.msg_iovlen = 1;
            rx_msgvec_[i].msg_hdr.msg_control = &rx_controls_[i * CONTROL_BUFFER_SIZE];
            rx_msgvec_[i].msg_hdr.msg_controllen = CONTROL_BUFFER_SIZE;
        }

        int const recvd =
            recvmmsg(sock_, rx_msgvec_.data(), static_cast<unsigned int>(recv_batch_size_), MSG_DONTWAIT, nullptr);

        if (recvd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            perror("recvmmsg");
            break;
        }

        if (recvd == 0) {
            break;
        }

        for (int msg_index = 0; msg_index < recvd; ++msg_index) {
            size_t const rx_idx = static_cast<size_t>(msg_index);
            ssize_t const packet_len = rx_msgvec_[rx_idx].msg_len;
            if (packet_len < static_cast<ssize_t>(sizeof(IcmpHdr))) {
                continue;
            }

            int ttl{-1};
            timespec recv_ts{0, 0};
            bool has_recv_ts{false};

            extract_control_data(msg_index, ttl, recv_ts, has_recv_ts);
            process_received_packet(msg_index, recv_ts, ttl, active_probes, hosts_found, scan_results);
        }

        if (static_cast<uint32_t>(recvd) < recv_batch_size_) {
            break;
        }
    }
}

void PingScanner::reap_timed_out_probes(size_t& active_probes) {
    timespec current_time{};
    clock_gettime(CLOCK_REALTIME, &current_time);

    int64_t const timeout_ns = static_cast<int64_t>(timeout_ms_) * NANOSECONDS_PER_MILLISECOND_LL;

    for (size_t slot = 0; slot < probe_table_.size(); ++slot) {
        ProbeInfo& probe = probe_table_[slot];
        if (!probe.active) {
            continue;
        }

        int64_t const elapsed_ns = ((current_time.tv_sec - probe.send_time.tv_sec) * NANOSECONDS_PER_SECOND_LL) +
                                   (current_time.tv_nsec - probe.send_time.tv_nsec);

        if (elapsed_ns > timeout_ns) {
            int const host_idx = host_index_for_ip(probe.dest_ip);
            if (host_idx >= 0 && host_to_probe_[static_cast<size_t>(host_idx)] == static_cast<int>(slot)) {
                host_to_probe_[static_cast<size_t>(host_idx)] = -1;
            }

            probe.active = false;
            if (active_probes > 0) {
                --active_probes;
            }
            ++probe_timeouts_;
        }
    }
}

}  // namespace netscan
