#include "jtool.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <cerrno>
#include <sys/random.h>
#include <termios.h>
#include <unistd.h>

namespace {

constexpr std::size_t DEFAULT_PASSWORD_LENGTH = 12;
constexpr std::size_t MAX_PASSWORD_LENGTH = 4096;
constexpr std::size_t MAX_ENTROPY_LENGTH = 1024;
constexpr std::uint32_t PRINTABLE_ASCII_COUNT = 94;

class TerminalEchoGuard {
public:
    TerminalEchoGuard() {
        if (!isatty(STDIN_FILENO) ||
            tcgetattr(STDIN_FILENO, &original_) != 0) {
            return;
        }

        termios hidden = original_;
        hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);

        active_ = tcsetattr(
            STDIN_FILENO,
            TCSAFLUSH,
            &hidden
        ) == 0;
    }

    TerminalEchoGuard(const TerminalEchoGuard&) = delete;
    TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

    ~TerminalEchoGuard() {
        if (active_) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
        }
    }

private:
    termios original_{};
    bool active_ = false;
};

std::size_t parse_length(std::string_view text) {
    unsigned long long value = 0;

    const char* begin = text.data();
    const char* end = begin + text.size();

    const auto result = std::from_chars(begin, end, value);

    if (result.ec != std::errc{} ||
        result.ptr != end ||
        value == 0 ||
        value > MAX_PASSWORD_LENGTH) {
        throw std::invalid_argument(
            "password length must be an integer from 1 to 4096"
        );
    }

    return static_cast<std::size_t>(value);
}

std::string read_entropy_text() {
    std::cerr
        << "Enter 1-1024 arbitrary characters "
        << "for additional entropy: ";

    std::string text;

    {
        TerminalEchoGuard echo_guard;

        if (!std::getline(std::cin, text)) {
            throw std::runtime_error(
                "failed to read entropy text"
            );
        }
    }

    if (isatty(STDIN_FILENO)) {
        std::cerr << '\n';
    }

    if (text.empty() || text.size() > MAX_ENTROPY_LENGTH) {
        throw std::invalid_argument(
            "entropy text length must be from 1 to 1024 characters"
        );
    }

    return text;
}

std::uint64_t calculate_checksum(std::string_view text) {
    std::uint64_t checksum = 14695981039346656037ULL;

    for (const unsigned char character : text) {
        checksum ^= character;
        checksum *= 1099511628211ULL;
    }

    checksum ^= static_cast<std::uint64_t>(text.size());
    checksum *= 1099511628211ULL;

    return checksum;
}

std::uint32_t get_os_random_word() {
    std::uint32_t value = 0;

    auto* output =
        reinterpret_cast<unsigned char*>(&value);

    std::size_t written = 0;

    while (written < sizeof(value)) {
        const ssize_t result = getrandom(
            output + written,
            sizeof(value) - written,
            0
        );

        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }

            throw std::runtime_error(
                std::string("getrandom failed: ") +
                std::strerror(errno)
            );
        }

        if (result == 0) {
            throw std::runtime_error(
                "getrandom returned no data"
            );
        }

        written += static_cast<std::size_t>(result);
    }

    return value;
}

class EntropyMixer {
public:
    explicit EntropyMixer(std::uint64_t user_checksum)
        : state_(
              user_checksum ^
              static_cast<std::uint64_t>(
                  std::chrono::high_resolution_clock::now()
                      .time_since_epoch()
                      .count()
              )
          ) {}

    std::uint32_t next_word() {
        state_ += 0x9E3779B97F4A7C15ULL;

        std::uint64_t mixed = state_;

        mixed =
            (mixed ^ (mixed >> 30U)) *
            0xBF58476D1CE4E5B9ULL;

        mixed =
            (mixed ^ (mixed >> 27U)) *
            0x94D049BB133111EBULL;

        mixed ^= mixed >> 31U;

        const std::uint32_t user_part =
            static_cast<std::uint32_t>(
                mixed ^ (mixed >> 32U)
            );

        return get_os_random_word() ^ user_part;
    }

private:
    std::uint64_t state_;
};

char generate_char(EntropyMixer& entropy) {
    constexpr std::uint64_t RANDOM_RANGE =
        std::uint64_t{1} << 32U;

    constexpr std::uint64_t ACCEPTED_LIMIT =
        RANDOM_RANGE -
        (RANDOM_RANGE % PRINTABLE_ASCII_COUNT);

    std::uint32_t value = 0;

    do {
        value = entropy.next_word();
    } while (
        static_cast<std::uint64_t>(value) >= ACCEPTED_LIMIT
    );

    return static_cast<char>(
        '!' + (value % PRINTABLE_ASCII_COUNT)
    );
}

std::string generate_password(
    std::size_t length,
    std::uint64_t user_checksum
) {
    EntropyMixer entropy(user_checksum);
    std::string password(length, '\0');

    for (char& character : password) {
        character = generate_char(entropy);
    }

    return password;
}

void print_usage() {
    std::cout
        << "Usage: jtool pass_gen [-n <length>]\n"
        << "  -n <length>  password length from 1 to 4096 "
        << "(default: 12)\n";
}

int pass_gen(const jtool::Arguments& arguments) {
    if (arguments.size() == 1 &&
        (arguments[0] == "-h" ||
         arguments[0] == "--help")) {
        print_usage();
        return 0;
    }

    std::size_t length = DEFAULT_PASSWORD_LENGTH;

    if (!arguments.empty()) {
        if (arguments.size() != 2 ||
            arguments[0] != "-n") {
            print_usage();
            return 2;
        }

        length = parse_length(arguments[1]);
    }

    const std::string entropy_text =
        read_entropy_text();

    const std::uint64_t user_checksum =
        calculate_checksum(entropy_text);

    const std::string password =
        generate_password(length, user_checksum);

    std::cout << password << '\n';

    return 0;
}

const jtool::Command pass_gen_command(
    {"pass_gen"},
    "generate a password using kernel and user-provided entropy",
    pass_gen
);

} // namespace
