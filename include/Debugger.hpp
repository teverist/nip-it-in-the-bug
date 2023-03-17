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
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {
            auto fd = open(m_prog_name.c_str(), O_RDONLY);
        }

        m_elf = elf::elf{elf::create_mmap_loader(fd)};
        m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};


    void set_breakpoint_at_address(std::intptr_t addr);

    void run();

private:
    std::string m_prog_name;
    pid_t m_pid;
    std::unordered_map<std::intptr_t, std::unique_ptr<Breakpoint>> m_breakpoints;

    elf::elf m_elf;
    dwarf::dwarf m_dwarf;
};


#endif // DEBUGGER_HPP

