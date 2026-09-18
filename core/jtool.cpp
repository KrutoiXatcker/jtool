#include "jtool.hpp"

#include <algorithm>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <utility>

namespace jtool {

namespace {

bool starts_with(const std::vector<std::string> &value,
                 const std::vector<std::string> &prefix) {
    return value.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), value.begin());
}

std::string join(const std::vector<std::string> &parts) {
    std::string result;
    for (const auto &part : parts) {
        if (!result.empty()) {
            result += ' ';
        }
        result += part;
    }
    return result;
}

} // namespace

Registry &Registry::instance() {
    static Registry registry;
    return registry;
}

void Registry::add(std::vector<std::string> path,
                   std::string description,
                   Handler handler) {
    if (path.empty() || !handler) {
        std::cerr << "jtool: invalid command registration\n";
        std::exit(2);
    }

    const auto duplicate = std::find_if(
        commands_.begin(), commands_.end(),
        [&path](const CommandInfo &command) { return command.path == path; });

    if (duplicate != commands_.end()) {
        std::cerr << "jtool: duplicate command: " << join(path) << '\n';
        std::exit(2);
    }

    commands_.push_back({std::move(path), std::move(description),
                         std::move(handler)});
}

bool Registry::has_prefix(const std::vector<std::string> &prefix) const {
    return std::any_of(commands_.begin(), commands_.end(),
        [&prefix](const CommandInfo &command) {
            return starts_with(command.path, prefix);
        });
}

void Registry::print_help(const std::vector<std::string> &prefix) const {
    if (prefix.empty()) {
        std::cout << "Usage: jtool <command> [arguments]\n\nCommands:\n";
    } else {
        std::cout << "Commands under '" << join(prefix) << "':\n";
    }

    std::vector<const CommandInfo *> visible;
    for (const auto &command : commands_) {
        if (starts_with(command.path, prefix)) {
            visible.push_back(&command);
        }
    }

    std::sort(visible.begin(), visible.end(),
        [](const CommandInfo *left, const CommandInfo *right) {
            return left->path < right->path;
        });

    for (const auto *command : visible) {
        std::cout << "  " << join(command->path);
        if (!command->description.empty()) {
            std::cout << " - " << command->description;
        }
        std::cout << '\n';
    }

    if (visible.empty()) {
        std::cout << "  No commands found.\n";
    }

    if (prefix.empty()) {
        std::cout << "\nUse: jtool help <command path>\n";
    }
}

int Registry::run(int argc, char **argv) const {
    std::vector<std::string> input;
    for (int index = 1; index < argc; ++index) {
        input.emplace_back(argv[index]);
    }

    if (input.empty() || input[0] == "--help" || input[0] == "-h") {
        print_help();
        return 0;
    }

    if (input[0] == "help") {
        const std::vector<std::string> prefix(input.begin() + 1, input.end());
        if (!prefix.empty() && !has_prefix(prefix)) {
            std::cerr << "jtool: unknown command path: " << join(prefix) << '\n';
            return 2;
        }
        print_help(prefix);
        return 0;
    }

    const CommandInfo *selected = nullptr;
    for (const auto &command : commands_) {
        if (starts_with(input, command.path) &&
            (selected == nullptr || command.path.size() > selected->path.size())) {
            selected = &command;
        }
    }

    if (selected == nullptr) {
        if (has_prefix(input)) {
            print_help(input);
            return 0;
        }
        std::cerr << "jtool: unknown command: " << join(input) << '\n';
        std::cerr << "Use 'jtool --help' to list commands.\n";
        return 2;
    }

    const Arguments arguments(
        input.begin() + static_cast<std::ptrdiff_t>(selected->path.size()),
        input.end());

    try {
        return selected->handler(arguments);
    } catch (const std::exception &error) {
        std::cerr << "jtool: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "jtool: unknown module error\n";
        return 1;
    }
}

Command::Command(std::initializer_list<const char *> path,
                 const char *description,
                 Handler handler) {
    std::vector<std::string> command_path;
    command_path.reserve(path.size());
    for (const char *part : path) {
        command_path.emplace_back(part);
    }

    Registry::instance().add(
        std::move(command_path),
        description == nullptr ? "" : description,
        std::move(handler));
}

} // namespace jtool

