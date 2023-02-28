#ifndef DEBUGGER_HPP
#define DEBUGGER_HPP


#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "Breakpoint.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

class Debugger {
public:
    Debugger (std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

    void run();

private:
    std::string m_prog_name;
    pid_t m_pid;
};


#endif // DEBUGGER_HPP