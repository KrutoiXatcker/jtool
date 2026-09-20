#include "jtool.hpp"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
constexpr std::uint64_t max_targets = 65536;

struct AliveHost {
    std::uint32_t ip;
    double rtt_ms;
};

bool parse_number(const std::string &text,
                  std::uint32_t minimum,
                  std::uint32_t maximum,
                  std::uint32_t &result) {
    if (text.empty()) {
        return false;
    }

    std::uint32_t value = 0;
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), value);

    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        value < minimum || value > maximum) {
        return false;
    }

    result = value;
    return true;
}

bool parse_ipv4(const std::string &text, std::uint32_t &result) {
    in_addr address{};
    if (inet_pton(AF_INET, text.c_str(), &address) != 1) {
        return false;
    }

    result = ntohl(address.s_addr);
    return true;
}

std::string ipv4_to_string(std::uint32_t value) {
    in_addr address{};
    address.s_addr = htonl(value);

    char buffer[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
        return "unknown";
    }

    return buffer;
}

bool append_range(std::uint32_t first,
                  std::uint32_t last,
                  std::vector<std::uint32_t> &targets,
                  std::string &error) {
    if (first > last) {
        error = "the first IP address is greater than the last one";
        return false;
    }

    const std::uint64_t count =
        static_cast<std::uint64_t>(last) - first + 1;

    if (count > max_targets) {
        error = "target contains more than 65536 IPv4 addresses";
        return false;
    }

    targets.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t ip = first; ip <= last; ++ip) {
        targets.push_back(static_cast<std::uint32_t>(ip));
    }

    return true;
}

bool parse_cidr(const std::string &text,
                std::vector<std::uint32_t> &targets,
                std::string &error) {
    const std::size_t slash = text.find('/');
    if (slash == std::string::npos ||
        text.find('/', slash + 1) != std::string::npos) {
        error = "invalid CIDR notation";
        return false;
    }

    std::uint32_t address = 0;
    std::uint32_t prefix = 0;
    if (!parse_ipv4(text.substr(0, slash), address) ||
        !parse_number(text.substr(slash + 1), 0, 32, prefix)) {
        error = "invalid IPv4 CIDR";
        return false;
    }

    const std::uint32_t mask =
        prefix == 0 ? 0 : 0xffffffffu << (32u - prefix);
    const std::uint32_t network = address & mask;
    const std::uint64_t address_count = 1ull << (32u - prefix);

    std::uint64_t first = network;
    std::uint64_t last = static_cast<std::uint64_t>(network) +
                         address_count - 1;

    // Skip network and broadcast for regular IPv4 subnets.
    // Both addresses remain valid for /31, and /32 contains one host.
    if (prefix <= 30) {
        ++first;
        --last;
    }

    if (last - first + 1 > max_targets) {
        error = "CIDR contains more than 65536 usable IPv4 addresses";
        return false;
    }

    return append_range(static_cast<std::uint32_t>(first),
                        static_cast<std::uint32_t>(last), targets, error);
}

bool parse_targets(const std::string &text,
                   std::vector<std::uint32_t> &targets,
                   std::string &error) {
    if (text.find('/') != std::string::npos) {
        return parse_cidr(text, targets, error);
    }

    const std::size_t dash = text.find('-');
    if (dash != std::string::npos) {
        if (text.find('-', dash + 1) != std::string::npos) {
            error = "invalid IPv4 range";
            return false;
        }

        std::uint32_t first = 0;
        std::uint32_t last = 0;
        if (!parse_ipv4(text.substr(0, dash), first) ||
            !parse_ipv4(text.substr(dash + 1), last)) {
            error = "invalid IPv4 range";
            return false;
        }

        return append_range(first, last, targets, error);
    }

    std::uint32_t address = 0;
    if (!parse_ipv4(text, address)) {
        error = "invalid IPv4 address";
        return false;
    }

    targets.push_back(address);
    return true;
}

std::uint16_t internet_checksum(const void *data, std::size_t size) {
    const auto *bytes = static_cast<const std::uint8_t *>(data);
    std::uint32_t sum = 0;

    while (size >= 2) {
        std::uint16_t word = 0;
        std::memcpy(&word, bytes, sizeof(word));
        sum += word;
        bytes += 2;
        size -= 2;
    }

    if (size == 1) {
        sum += *bytes;
    }

    while (sum >> 16u) {
        sum = (sum & 0xffffu) + (sum >> 16u);
    }

    return static_cast<std::uint16_t>(~sum);
}

std::array<std::uint8_t, 64> make_request(std::uint16_t identifier,
                                          std::uint16_t sequence) {
    std::array<std::uint8_t, 64> packet{};
    auto *header = reinterpret_cast<icmphdr *>(packet.data());

    header->type = ICMP_ECHO;
    header->code = 0;
    header->un.echo.id = htons(identifier);
    header->un.echo.sequence = htons(sequence);

    for (std::size_t index = sizeof(icmphdr); index < packet.size(); ++index) {
        packet[index] = static_cast<std::uint8_t>(index & 0xffu);
    }

    header->checksum = 0;
    header->checksum = internet_checksum(packet.data(), packet.size());
    return packet;
}

int create_icmp_socket(bool &raw_socket) {
    raw_socket = false;

    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (socket_fd >= 0) {
        return socket_fd;
    }

    raw_socket = true;
    return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

bool wait_for_reply(int socket_fd,
                    bool raw_socket,
                    std::uint32_t expected_ip,
                    std::uint16_t identifier,
                    std::uint16_t sequence,
                    std::uint32_t timeout_ms,
                    const Clock::time_point &started,
                    double &rtt_ms) {
    const auto deadline = started + std::chrono::milliseconds(timeout_ms);
    std::array<std::uint8_t, 2048> buffer{};

    while (Clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now());

        pollfd event{socket_fd, POLLIN, 0};
        const int poll_result = poll(
            &event, 1, static_cast<int>(std::max<std::int64_t>(1, remaining.count())));

        if (poll_result <= 0) {
            return false;
        }

        sockaddr_in sender{};
        socklen_t sender_size = sizeof(sender);
        const ssize_t received = recvfrom(
            socket_fd, buffer.data(), buffer.size(), 0,
            reinterpret_cast<sockaddr *>(&sender), &sender_size);

        if (received <= 0 || ntohl(sender.sin_addr.s_addr) != expected_ip) {
            continue;
        }

        std::size_t offset = 0;
        if (raw_socket) {
            if (static_cast<std::size_t>(received) < sizeof(iphdr)) {
                continue;
            }

            const auto *ip_header =
                reinterpret_cast<const iphdr *>(buffer.data());
            offset = static_cast<std::size_t>(ip_header->ihl) * 4u;
        }

        if (static_cast<std::size_t>(received) < offset + sizeof(icmphdr)) {
            continue;
        }

        const auto *icmp_header =
            reinterpret_cast<const icmphdr *>(buffer.data() + offset);

        if (icmp_header->type != ICMP_ECHOREPLY ||
            ntohs(icmp_header->un.echo.sequence) != sequence) {
            continue;
        }

        // Linux ping sockets may replace the identifier. Raw sockets do not.
        if (raw_socket && ntohs(icmp_header->un.echo.id) != identifier) {
            continue;
        }

        rtt_ms = std::chrono::duration<double, std::milli>(
            Clock::now() - started).count();
        return true;
    }

    return false;
}

bool probe(int socket_fd,
           bool raw_socket,
           std::uint32_t ip,
           std::uint16_t identifier,
           std::uint16_t sequence,
           std::uint32_t timeout_ms,
           double &rtt_ms) {
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(ip);

    const auto packet = make_request(identifier, sequence);
    const auto started = Clock::now();

    const ssize_t sent = sendto(
        socket_fd, packet.data(), packet.size(), 0,
        reinterpret_cast<const sockaddr *>(&destination), sizeof(destination));

    if (sent != static_cast<ssize_t>(packet.size())) {
        return false;
    }

    return wait_for_reply(socket_fd, raw_socket, ip, identifier, sequence,
                          timeout_ms, started, rtt_ms);
}

void print_help() {
    std::cout
        << "Usage:\n"
        << "  jtool icmp scan <target> [options]\n\n"
        << "Targets (IPv4):\n"
        << "  192.168.1.10\n"
        << "  192.168.1.0/24\n"
        << "  192.168.1.10-192.168.1.50\n\n"
        << "Options:\n"
        << "  --timeout MS    reply timeout, default: 500\n"
        << "  --threads N     worker count, default: 64\n"
        << "  --retries N     requests per host, default: 1\n";
}

int icmp_scan(const jtool::Arguments &arguments) {
    if (arguments.empty() || arguments[0] == "--help" ||
        arguments[0] == "-h") {
        print_help();
        return arguments.empty() ? 2 : 0;
    }

    std::vector<std::uint32_t> targets;
    std::string error;
    if (!parse_targets(arguments[0], targets, error)) {
        std::cerr << "icmp scan: " << error << '\n';
        return 2;
    }

    std::uint32_t timeout_ms = 500;
    std::uint32_t thread_count = 64;
    std::uint32_t retries = 1;

    for (std::size_t index = 1; index < arguments.size();) {
        const std::string &option = arguments[index++];
        if (index >= arguments.size()) {
            std::cerr << "icmp scan: " << option << " requires a value\n";
            return 2;
        }

        const std::string &value = arguments[index++];
        if (option == "--timeout") {
            if (!parse_number(value, 1, 60000, timeout_ms)) {
                std::cerr << "icmp scan: timeout must be 1-60000 ms\n";
                return 2;
            }
        } else if (option == "--threads") {
            if (!parse_number(value, 1, 512, thread_count)) {
                std::cerr << "icmp scan: threads must be 1-512\n";
                return 2;
            }
        } else if (option == "--retries") {
            if (!parse_number(value, 1, 10, retries)) {
                std::cerr << "icmp scan: retries must be 1-10\n";
                return 2;
            }
        } else {
            std::cerr << "icmp scan: unknown option: " << option << '\n';
            return 2;
        }
    }

    bool test_raw_socket = false;
    const int test_socket = create_icmp_socket(test_raw_socket);
    if (test_socket < 0) {
        std::cerr << "icmp scan: cannot create ICMP socket: "
                  << std::strerror(errno) << '\n'
                  << "Try running as root or grant CAP_NET_RAW to jtool.\n";
        return 1;
    }
    close(test_socket);

    thread_count = static_cast<std::uint32_t>(
        std::min<std::size_t>(thread_count, targets.size()));

    std::cout << "Scanning " << targets.size() << " host(s) with ICMP, "
              << retries << " request(s) per host...\n";

    std::atomic<std::size_t> next_target{0};
    std::vector<std::vector<AliveHost>> worker_results(thread_count);
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (std::uint32_t worker = 0; worker < thread_count; ++worker) {
        workers.emplace_back([&, worker] {
            bool raw_socket = false;
            const int socket_fd = create_icmp_socket(raw_socket);
            if (socket_fd < 0) {
                return;
            }

            const std::uint16_t identifier = static_cast<std::uint16_t>(
                (getpid() + worker + 1) & 0xffffu);
            auto &result = worker_results[worker];

            while (true) {
                const std::size_t target_index = next_target.fetch_add(1);
                if (target_index >= targets.size()) {
                    break;
                }

                for (std::uint32_t attempt = 0; attempt < retries; ++attempt) {
                    const std::uint16_t sequence = static_cast<std::uint16_t>(
                        ((target_index * retries + attempt) % 65535u) + 1u);
                    double rtt_ms = 0.0;

                    if (probe(socket_fd, raw_socket, targets[target_index],
                              identifier, sequence, timeout_ms, rtt_ms)) {
                        result.push_back({targets[target_index], rtt_ms});
                        break;
                    }
                }
            }

            close(socket_fd);
        });
    }

    for (auto &worker : workers) {
        worker.join();
    }

    std::vector<AliveHost> alive_hosts;
    for (auto &result : worker_results) {
        alive_hosts.insert(alive_hosts.end(), result.begin(), result.end());
    }

    std::sort(alive_hosts.begin(), alive_hosts.end(),
        [](const AliveHost &left, const AliveHost &right) {
            return left.ip < right.ip;
        });

    for (const auto &host : alive_hosts) {
        std::cout << ipv4_to_string(host.ip)
                  << " alive time=" << std::fixed << std::setprecision(2)
                  << host.rtt_ms << " ms\n";
    }

    std::cout << "Finished. Scanned: " << targets.size()
              << ", alive: " << alive_hosts.size() << '\n';
    return 0;
}

const jtool::Command icmp_scan_command(
    {"icmp", "scan"},
    "discover IPv4 hosts using ICMP echo requests",
    icmp_scan);

} // namespace

