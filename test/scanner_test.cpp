#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "net_scan.h"


void SplitCIDRTest()
{
    char cidr_char_arr[] = "127.3.55.1/13";
    std::string cidr_string{cidr_char_arr};
    size_t slash_pos = cidr_string.find('/');

    std::string ip_addr_string{};
    int num_prefix_bits = 32;
    SplitCIDR(cidr_string, slash_pos, ip_addr_string, num_prefix_bits);

    assert( std::memcmp(ip_addr_string.c_str(), cidr_char_arr, ip_addr_string.length()*sizeof(char)) == 0 &&
            "SplitCIDRTest: ip_addr_string failed.\n");
    assert( num_prefix_bits == 13 && "SplitCIDRTest: num_prefix_bits failed.\n");
}

void DetermineIPRange()
{
    int num_prefix_bits = 13;
    char ip_addr_char_arr[] = "127.3.55.1";

    uint32_t start_ip_uint = IPAddrStrToUInt32(ip_addr_char_arr);
    uint32_t end_ip_uint = 0;
    DetermineIPRange(num_prefix_bits, start_ip_uint, end_ip_uint);
    // start_ip_uint should be equivalent to 127.0.0.0
    // end_ip_uint should be equivalent to 127.7.255.255

    assert( start_ip_uint == 2130706432 && "SplitCIDRTest: start_ip_uint failed.\n");
    assert( end_ip_uint == 2131230719   && "SplitCIDRTest: num_prefix_bits failed.\n");

//    // Uncomment and rerun for validation of 2130706432 and 2131230719.
//    char buf[INET_ADDRSTRLEN] = { 0 };
//    uint32_t network_order_uint = htonl(start_ip_uint);
//    inet_ntop(AF_INET, &network_order_uint, buf, INET_ADDRSTRLEN);
//    std::printf("start_ip_uint in string form %s\n", buf);
//    network_order_uint = htonl(end_ip_uint);
//    inet_ntop(AF_INET, &network_order_uint, buf, INET_ADDRSTRLEN);
//    std::printf("end_ip_uint in string form %s\n", buf);
}

// CheckPingTest1 mode=PING --> tests PingCheck() when host is down.
void CheckPingTest1()
{
    NetScan net_scan{};
    char ip_addr_char_arr[] = "127.255.255.255"; // Can not ping loopback broadcast address.
    Mode mode(Mode::PING);

    std::vector<std::string> host = net_scan.Check(ip_addr_char_arr, mode);
    assert( host.size() == 0 && "CheckPingTest1: failed, host.size() > 0.\n" );
}

// CheckPingTest2 mode=PING --> tests PingCheck() when host is up.
void CheckPingTest2()
{
    NetScan net_scan{};
    char ip_addr_char_arr[] = "127.0.0.1";
    Mode mode(Mode::PING);

    std::vector<std::string> host = net_scan.Check(ip_addr_char_arr, mode);
    std::string hostname = net_scan.GetHostname();
    std::string check_string = ip_addr_char_arr;
    assert( host[0] == check_string &&
            "CheckPingTest2: failed, ip_addr_string does not match.\n");
    assert( host[1] == hostname &&
            "CheckPingTest2: failed, ip_addr_string does not match.\n");
}

// CheckConnectTest1 mode=CONNECT --> tests ConnectCheck() when host is down.
// Loopback broadcast address will result in ENETUNREACH thus causing ConnectCheck to report host down.
void CheckConnectTest1()
{
    NetScan net_scan{};
    char ip_addr_char_arr[] = "127.255.255.255";
    Mode mode(Mode::CONNECT);

    std::vector<std::string> host = net_scan.Check(ip_addr_char_arr, mode);
    assert( host.size() == 0 && "CheckConnectTest1: failed, host.size() > 0.\n" );
}

// CheckConnectTest2 mode=CONNECT --> tests ConnectCheck() when host is up.
// Lookback will return ECONNRESET indicating that host is up.
void CheckConnectTest2()
{
    NetScan net_scan{};
    char ip_addr_char_arr[] = "127.1.1.1";
    Mode mode(Mode::PING);

    std::vector<std::string> host = net_scan.Check(ip_addr_char_arr, mode);
    std::string hostname = net_scan.GetHostname();
    std::string check_string = ip_addr_char_arr;
    assert( host[0] == check_string &&
            "CheckConnectTest2: failed, ip_addr_string does not match.\n");
    assert( host[1] == hostname &&
            "CheckConnectTest2: failed, ip_addr_string does not match.\n");
}

void MockRemote(
    std::mutex& mtx,
    std::condition_variable& cv,
    int& count,
    const char *ip_addr_char_arr,
    int port
)
{
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        std::error_code ec(errno, std::system_category());
        throw std::system_error(ec, "Error: MockRemote, failed to create socket.\n");
    }
    // Avoid TIME_WAIT causing EADDRINUSE (address already in use) by setting setsockopt to SO_REUSEADDR, which can
    // occur if test is re-ran within a short time period.
    int enable = 1;
    int err = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if (err < 0) {
        close(sock_fd);
        std::error_code ec(errno, std::system_category());
        throw std::system_error(ec, "Error: MockRemote, failed to setsockopt SO_REUSEADDR.\n");
    }

    struct sockaddr_in recv_sockaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    recv_sockaddr.sin_family = AF_INET;
    recv_sockaddr.sin_port = htons(port);
    uint32_t ip_addr_uint32 = 0;
    err = inet_pton(AF_INET, ip_addr_char_arr, &ip_addr_uint32);
    if (err < 1)
    {
        close(sock_fd);
        throw std::invalid_argument("Error: MockRemote, invalid ip_addr_char_arr.");
    }
    recv_sockaddr.sin_addr.s_addr = ip_addr_uint32;

    err = bind(sock_fd, (struct sockaddr *)&recv_sockaddr, addrlen);
    if (err == -1) {
        close(sock_fd);
        std::error_code ec(errno, std::system_category());
        throw std::system_error(ec, "Error: MockRemote, failed bind socket.\n");
    }

    err = listen(sock_fd, 1);
    if (err == -1) {
        close(sock_fd);
        std::error_code ec(errno, std::system_category());
        throw std::system_error(ec, "Error: MockRemote, failed to listen socket.\n");
    }

    {
        std::unique_lock<std::mutex> lock(mtx);
        ++count;
        cv.notify_one();
    }

    close(sock_fd);
}

void CIDRScanTest()
{
    NetScan net_scan{};
    char ip_addr_char_arr[] = "127.255.255.255/30";
    std::string cidr_string{ip_addr_char_arr};
    size_t slash_pos = cidr_string.find('/');

    std::vector<std::string> check_ip_strings = {
        "127.255.255.252",
        "127.255.255.253",
        "127.255.255.254"
    };
    int num_ips = check_ip_strings.size();
    int num_hosts_up = num_ips;
    Mode mode(Mode::CONNECT);

    std::mutex mtx;
    std::condition_variable cv;
    int recv_sockets_ready = 0;
    std::string target_ip_addr{ip_addr_char_arr};
    int starting_port = 62001;
    int port = starting_port;
    std::vector<std::thread> threads;
    for (int t = 0; t < num_hosts_up; t++ )
    {
        const char *ip_addr_char_arr = check_ip_strings[t].c_str();
        std::thread curr_thread(
            MockRemote,
            std::ref(mtx),
            std::ref(cv),
            std::ref(recv_sockets_ready),
            ip_addr_char_arr,
            port
        );
        threads.emplace_back(std::move(curr_thread));
        port++;
    }

    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&] { return recv_sockets_ready == num_hosts_up; });
    }

    std::vector<std::vector<std::string>> hosts_avail = net_scan.CIDRScan(ip_addr_char_arr, slash_pos, mode);

    for (auto& thread : threads)
    {
        thread.join();
    }

    assert( static_cast<int>(hosts_avail.size()) == num_hosts_up && "CIDRScanTest: failed, host.size() > 0.\n" );
    // hostname will just be the same loopback address as hosts_avail[i][0] -- skipping.
    for (int i = 0; i < num_hosts_up; i++ )
    {
        assert( hosts_avail[i][0] == check_ip_strings[i] &&
                "CIDRScanTest: failed, returned host does not match check_ip_string.\n" );
    }
}

int main()
{
    SplitCIDRTest();
    DetermineIPRange();
    CheckPingTest1();
    CheckPingTest2();
    CheckConnectTest1();
    CheckConnectTest2();

    // Will leak (reachable) memory from getnameinfo() that fails to DNS resolve 127.255.255.252-255. Due to a libc
    // bug or avahi bug (probably avahi). See: https://sourceware.org/bugzilla/show_bug.cgi?id=14984
    // This is the reason for the suppression file.
    CIDRScanTest();

    return 0;
}
