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


    void set_breakpoint_at_address(std::intptr_t addr);

    void run();

private:
    std::string m_prog_name;
    pid_t m_pid;
    std::unordered_map<std::intptr_t, std::unique_ptr<Breakpoint>> m_breakpoints;
};


#endif // DEBUGGER_HPP

