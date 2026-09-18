#include "jtool.hpp"

int main(int argc, char **argv) {
    return jtool::Registry::instance().run(argc, argv);
}

