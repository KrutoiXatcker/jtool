#pragma once

#include <functional>
#include <initializer_list>
#include <string>
#include <vector>

namespace jtool {

using Arguments = std::vector<std::string>;
using Handler = std::function<int(const Arguments &)>;

struct CommandInfo {
    std::vector<std::string> path;
    std::string description;
    Handler handler;
};

class Registry {
public:
    static Registry &instance();

    void add(std::vector<std::string> path,
             std::string description,
             Handler handler);

    int run(int argc, char **argv) const;

private:
    void print_help(const std::vector<std::string> &prefix = {}) const;
    bool has_prefix(const std::vector<std::string> &prefix) const;

    std::vector<CommandInfo> commands_;
};

/*
 * Create one static Command object for every command path in a module.
 * Example: {"docker", "ps", "start"} becomes:
 *          jtool docker ps start
 */
class Command {
public:
    Command(std::initializer_list<const char *> path,
            const char *description,
            Handler handler);
};

} // namespace jtool

