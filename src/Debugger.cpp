
#include "Debugger.hpp"

void Debugger::run() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    char* line = nullptr;
    while((line = linenoise("minidbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}


void Debugger::handle_command(const std::string& line) {
    auto args = split(line,' ');
    auto command = args[0];

    if (is_prefix(command, "cont")) {
        continue_execution();
    }
    else if(is_prefix(command, "break")) {
        // Check that the user has given us an argument
        if (args.size() != 2) {
            std::cerr << "Please specify an address\n";
            return;
        }
        // Check that the argument is a valid hex number
        auto result = strtoul(args[1].c_str(), nullptr, 16);
        if (result == 0) {
            std::cerr << "Please specify a valid hex number\n";
            return;
        }        

        std::string addr {args[1], 2}; //naively assume that the user has written 0xADDRESS
        set_breakpoint_at_address(std::stol(addr, 0, 16));
    }
    else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        }
        else if (is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2}; //assume 0xVAL
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    }
    else if(is_prefix(command, "memory")) {
        std::string addr {args[2], 2}; //assume 0xADDRESS

        if (is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2}; //assume 0xVAL
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else {
        std::cerr << "Unknown command\n";
    }
}


void debugger::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}



std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;

    while (std::getline(ss,item,delimiter)) {
        out.push_back(item);
    }

    return out;
}

bool is_prefix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

void Debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address " << std::hex << addr << std::endl;
    auto breakpoint = std::make_unique<Breakpoint>(m_pid, addr);
    breakpoint->enable();
    m_breakpoints.insert({addr, std::move(breakpoint)});
}


// TODO: make an I/O manipulator to get rid of this mess.
void Debugger::dump_registers() {
    for (const auto& rd : g_register_descriptors) {
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;
    }
}


uint64_t Debugger::read_memory(uint64_t address) {
    m_iov.iov_base = reinterpret_cast<void*>(address);
    m_iov.iov_len = sizeof(uint64_t);
    return process_vm_readv(m_pid, &m_iov, 1, &m_iov, 1, 0);
}

void Debugger::write_memory(uint64_t address, uint64_t value) {
    m_iov.iov_base = reinterpret_cast<void*>(address);
    m_iov.iov_len = sizeof(value);
    m_iov.iov_base = &value;
    process_vm_writev(m_pid, &m_iov, 1, &m_iov, 1, 0);
}


uint64_t Debugger::get_pc() {
    return get_register_value(m_pid, Register::rip);
}

void Debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, Register::rip, pc);
}

void Debugger::step_over_breakpoint() {
    auto possible_breakpoint_location = get_pc() - 1; // -1 because we want to be on the breakpoint instruction
    if (m_breakpoints.count(possible_breakpoint_location)) {
        auto& bp = m_breakpoints[possible_breakpoint_location];

        if (bp.is_enabled()) {
            auto previous_instruction_address = possible_breakpoint_location;
            set_pc(previous_instruction_address);

            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}


void Debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

