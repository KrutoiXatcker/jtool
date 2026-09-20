#include "jtool.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

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

bool resolve_ipv4(const std::string &host,
                  sockaddr_in &destination,
                  std::string &address,
                  std::string &error) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo *result = nullptr;
    const int status = getaddrinfo(host.c_str(), nullptr, &hints, &result);
    if (status != 0) {
        error = gai_strerror(status);
        return false;
    }

    destination = *reinterpret_cast<sockaddr_in *>(result->ai_addr);
    freeaddrinfo(result);

    char buffer[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &destination.sin_addr,
                  buffer, sizeof(buffer)) == nullptr) {
        error = std::strerror(errno);
        return false;
    }

    address = buffer;
    return true;
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

bool wait_for_reply(int socket_fd,
                    bool raw_socket,
                    std::uint16_t identifier,
                    std::uint16_t sequence,
                    std::uint32_t timeout_ms,
                    std::string &source,
                    double &rtt_ms,
                    const Clock::time_point &started) {
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

        if (received <= 0) {
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

        char address_buffer[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &sender.sin_addr,
                      address_buffer, sizeof(address_buffer)) == nullptr) {
            source = "unknown";
        } else {
            source = address_buffer;
        }

        rtt_ms = std::chrono::duration<double, std::milli>(
            Clock::now() - started).count();
        return true;
    }

    return false;
}

void print_help() {
    std::cout
        << "Usage:\n"
        << "  jtool ping <host> [options]\n\n"
        << "Options:\n"
        << "  --count N       number of requests, default: 4\n"
        << "  --timeout MS    reply timeout, default: 1000\n"
        << "  --interval MS   delay between requests, default: 1000\n\n"
        << "Examples:\n"
        << "  jtool ping 8.8.8.8\n"
        << "  jtool ping example.com --count 5 --timeout 2000\n";
}

int ping_command(const jtool::Arguments &arguments) {
    if (arguments.empty() || arguments[0] == "--help" ||
        arguments[0] == "-h") {
        print_help();
        return arguments.empty() ? 2 : 0;
    }

    const std::string host = arguments[0];
    std::uint32_t count = 4;
    std::uint32_t timeout_ms = 1000;
    std::uint32_t interval_ms = 1000;

    for (std::size_t index = 1; index < arguments.size();) {
        const std::string &option = arguments[index++];
        if (index >= arguments.size()) {
            std::cerr << "ping: " << option << " requires a value\n";
            return 2;
        }

        const std::string &value = arguments[index++];
        if (option == "--count") {
            if (!parse_number(value, 1, 1000, count)) {
                std::cerr << "ping: count must be 1-1000\n";
                return 2;
            }
        } else if (option == "--timeout") {
            if (!parse_number(value, 1, 60000, timeout_ms)) {
                std::cerr << "ping: timeout must be 1-60000 ms\n";
                return 2;
            }
        } else if (option == "--interval") {
            if (!parse_number(value, 0, 60000, interval_ms)) {
                std::cerr << "ping: interval must be 0-60000 ms\n";
                return 2;
            }
        } else {
            std::cerr << "ping: unknown option: " << option << '\n';
            return 2;
        }
    }

    sockaddr_in destination{};
    std::string destination_address;
    std::string error;
    if (!resolve_ipv4(host, destination, destination_address, error)) {
        std::cerr << "ping: cannot resolve " << host << ": " << error << '\n';
        return 1;
    }

    bool raw_socket = false;
    const int socket_fd = create_icmp_socket(raw_socket);
    if (socket_fd < 0) {
        std::cerr << "ping: cannot create ICMP socket: "
                  << std::strerror(errno) << '\n'
                  << "Try running as root or grant CAP_NET_RAW to jtool.\n";
        return 1;
    }

    const std::uint16_t identifier =
        static_cast<std::uint16_t>(getpid() & 0xffff);
    std::uint32_t received_count = 0;
    std::vector<double> round_trip_times;

    std::cout << "PING " << host << " (" << destination_address
              << ") 56 bytes of data.\n";

    for (std::uint32_t current = 1; current <= count; ++current) {
        const auto planned_start = Clock::now();
        const auto packet = make_request(
            identifier, static_cast<std::uint16_t>(current));

        const auto started = Clock::now();
        const ssize_t sent = sendto(
            socket_fd, packet.data(), packet.size(), 0,
            reinterpret_cast<const sockaddr *>(&destination),
            sizeof(destination));

        if (sent != static_cast<ssize_t>(packet.size())) {
            std::cerr << "ping: send failed: " << std::strerror(errno) << '\n';
        } else {
            std::string source;
            double rtt_ms = 0.0;
            if (wait_for_reply(socket_fd, raw_socket, identifier,
                               static_cast<std::uint16_t>(current), timeout_ms,
                               source, rtt_ms, started)) {
                ++received_count;
                round_trip_times.push_back(rtt_ms);
                std::cout << "64 bytes from " << source
                          << ": icmp_seq=" << current
                          << " time=" << std::fixed << std::setprecision(2)
                          << rtt_ms << " ms\n";
            } else {
                std::cout << "Request timeout for icmp_seq " << current << '\n';
            }
        }

        if (current != count) {
            std::this_thread::sleep_until(
                planned_start + std::chrono::milliseconds(interval_ms));
        }
    }

    close(socket_fd);

    const double packet_loss =
        100.0 * static_cast<double>(count - received_count) / count;

    std::cout << "\n--- " << host << " ping statistics ---\n"
              << count << " packets transmitted, "
              << received_count << " received, "
              << std::fixed << std::setprecision(1)
              << packet_loss << "% packet loss\n";

    if (!round_trip_times.empty()) {
        const auto [minimum, maximum] = std::minmax_element(
            round_trip_times.begin(), round_trip_times.end());
        const double average = std::accumulate(
            round_trip_times.begin(), round_trip_times.end(), 0.0) /
            round_trip_times.size();

        std::cout << "rtt min/avg/max = "
                  << std::setprecision(2)
                  << *minimum << '/' << average << '/' << *maximum
                  << " ms\n";
    }

    return received_count == 0 ? 1 : 0;
}

const jtool::Command ping(
    {"ping"},
    "send ICMP echo requests to an IPv4 host",
    ping_command);

} // namespace

