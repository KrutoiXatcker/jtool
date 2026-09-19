#include "jtool.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr std::uint64_t max_targets = 65536;

struct OpenPort {
    std::uint32_t ip;
    std::uint16_t port;
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
        return {};
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

    // For ordinary subnets, do not scan network and broadcast addresses.
    // /31 and /32 contain usable addresses and are kept unchanged.
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

bool append_ports(std::uint32_t first,
                  std::uint32_t last,
                  std::vector<std::uint16_t> &ports,
                  std::string &error) {
    if (first > last) {
        error = "the first port is greater than the last one";
        return false;
    }

    for (std::uint32_t port = first; port <= last; ++port) {
        ports.push_back(static_cast<std::uint16_t>(port));
    }

    return true;
}

bool parse_ports(const std::string &text,
                 std::vector<std::uint16_t> &ports,
                 std::string &error) {
    std::size_t begin = 0;

    while (begin <= text.size()) {
        const std::size_t comma = text.find(',', begin);
        const std::string item = text.substr(
            begin, comma == std::string::npos ? std::string::npos
                                               : comma - begin);

        if (item.empty()) {
            error = "empty port value";
            return false;
        }

        const std::size_t dash = item.find('-');
        std::uint32_t first = 0;
        std::uint32_t last = 0;

        if (dash == std::string::npos) {
            if (!parse_number(item, 1, 65535, first)) {
                error = "invalid port: " + item;
                return false;
            }
            last = first;
        } else {
            if (item.find('-', dash + 1) != std::string::npos ||
                !parse_number(item.substr(0, dash), 1, 65535, first) ||
                !parse_number(item.substr(dash + 1), 1, 65535, last)) {
                error = "invalid port range: " + item;
                return false;
            }
        }

        if (!append_ports(first, last, ports, error)) {
            return false;
        }

        if (comma == std::string::npos) {
            break;
        }
        begin = comma + 1;
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return !ports.empty();
}

bool port_is_open(std::uint32_t ip,
                  std::uint16_t port,
                  int timeout_ms) {
    const int socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        return false;
    }

    const int old_flags = fcntl(socket_fd, F_GETFL, 0);
    if (old_flags < 0 ||
        fcntl(socket_fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        close(socket_fd);
        return false;
    }

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(port);
    destination.sin_addr.s_addr = htonl(ip);

    int result = connect(socket_fd,
                         reinterpret_cast<sockaddr *>(&destination),
                         sizeof(destination));

    if (result < 0 && errno == EINPROGRESS) {
        pollfd event{socket_fd, POLLOUT, 0};
        result = poll(&event, 1, timeout_ms);

        if (result > 0) {
            int socket_error = 0;
            socklen_t error_size = sizeof(socket_error);
            result = getsockopt(socket_fd, SOL_SOCKET, SO_ERROR,
                                &socket_error, &error_size);
            result = result == 0 && socket_error == 0 ? 0 : -1;
        } else {
            result = -1;
        }
    }

    close(socket_fd);
    return result == 0;
}

void print_help() {
    std::cout
        << "Usage:\n"
        << "  jtool tcp scan <target> [ports] [options]\n\n"
        << "Targets (IPv4):\n"
        << "  192.168.1.10\n"
        << "  192.168.1.0/24\n"
        << "  192.168.1.10-192.168.1.50\n\n"
        << "Ports:\n"
        << "  not specified  scan all ports 1-65535\n"
        << "  22             one port\n"
        << "  22,80,443      port list\n"
        << "  1-1024         port range\n"
        << "  22,80,8000-8100 combined list\n\n"
        << "Options:\n"
        << "  --timeout MS    connect timeout, default: 300\n"
        << "  --threads N     worker count, default: 64\n";
}

int tcp_scan(const jtool::Arguments &arguments) {
    if (arguments.empty() || arguments[0] == "--help" ||
        arguments[0] == "-h") {
        print_help();
        return arguments.empty() ? 2 : 0;
    }

    std::vector<std::uint32_t> targets;
    std::string error;
    if (!parse_targets(arguments[0], targets, error)) {
        std::cerr << "tcp scan: " << error << '\n';
        return 2;
    }

    std::vector<std::uint16_t> ports;
    std::size_t index = 1;

    if (index < arguments.size() &&
        arguments[index].rfind("--", 0) != 0) {
        if (!parse_ports(arguments[index], ports, error)) {
            std::cerr << "tcp scan: " << error << '\n';
            return 2;
        }
        ++index;
    } else {
        ports.reserve(65535);
        for (std::uint32_t port = 1; port <= 65535; ++port) {
            ports.push_back(static_cast<std::uint16_t>(port));
        }
    }

    std::uint32_t timeout_ms = 300;
    std::uint32_t thread_count = 64;

    while (index < arguments.size()) {
        const std::string &option = arguments[index++];
        if (index >= arguments.size()) {
            std::cerr << "tcp scan: " << option << " requires a value\n";
            return 2;
        }

        const std::string &value = arguments[index++];
        if (option == "--timeout") {
            if (!parse_number(value, 1, 60000, timeout_ms)) {
                std::cerr << "tcp scan: timeout must be 1-60000 ms\n";
                return 2;
            }
        } else if (option == "--threads") {
            if (!parse_number(value, 1, 512, thread_count)) {
                std::cerr << "tcp scan: threads must be 1-512\n";
                return 2;
            }
        } else {
            std::cerr << "tcp scan: unknown option: " << option << '\n';
            return 2;
        }
    }

    const std::uint64_t total =
        static_cast<std::uint64_t>(targets.size()) * ports.size();
    thread_count = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(thread_count, total));

    std::cout << "Scanning " << targets.size() << " host(s), "
              << ports.size() << " port(s), " << total
              << " connection attempt(s)...\n";

    std::atomic<std::uint64_t> next_task{0};
    std::vector<std::vector<OpenPort>> worker_results(thread_count);
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (std::uint32_t worker = 0; worker < thread_count; ++worker) {
        workers.emplace_back([&, worker] {
            auto &result = worker_results[worker];

            while (true) {
                const std::uint64_t task = next_task.fetch_add(1);
                if (task >= total) {
                    break;
                }

                const std::size_t target_index =
                    static_cast<std::size_t>(task / ports.size());
                const std::size_t port_index =
                    static_cast<std::size_t>(task % ports.size());

                if (port_is_open(targets[target_index], ports[port_index],
                                 static_cast<int>(timeout_ms))) {
                    result.push_back(
                        {targets[target_index], ports[port_index]});
                }
            }
        });
    }

    for (auto &worker : workers) {
        worker.join();
    }

    std::vector<OpenPort> open_ports;
    for (auto &result : worker_results) {
        open_ports.insert(open_ports.end(), result.begin(), result.end());
    }

    std::sort(open_ports.begin(), open_ports.end(),
        [](const OpenPort &left, const OpenPort &right) {
            if (left.ip != right.ip) {
                return left.ip < right.ip;
            }
            return left.port < right.port;
        });

    for (const auto &entry : open_ports) {
        std::cout << ipv4_to_string(entry.ip) << ':' << entry.port
                  << " open\n";
    }

    std::cout << "Finished. Open ports: " << open_ports.size() << '\n';
    return 0;
}

const jtool::Command tcp_scan_command(
    {"tcp", "scan"},
    "TCP connect scan for IPv4 address, CIDR or range",
    tcp_scan);

} // namespace

