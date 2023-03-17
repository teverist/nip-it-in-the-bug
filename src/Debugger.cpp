
#include "Debugger.hpp"

void Debugger::run() {
    wait_for_signal();
    initialise_load_address();

    char* line = nullptr;
    while((line = linenoise("nip> ")) != nullptr) {
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


    auto siginfo = get_signal_info();
    switch (siginfo.si_signo) {
        case SIGTRAP:
            handle_sigtrap(siginfo);
            break;
        case SIGSEGV:
            std::cout << "SEGFAULT: " << siginfo.si_code << std::endl;
            break;
        default:
            std::cout << "Unknown signal " << siginfo.si_signo << std::endl;
            break;
    }
}

dwarf::die Debugger::get_function_from_pc(uint64_t pc) {
    auto& cu = m_dwarf.compilation_units()[0];
    auto& root = cu.root();
    auto iter = root.begin();
    while (iter != root.end()) {
        if (iter->tag == dwarf::DW_TAG::subprogram) {
            auto low_pc = iter->find(dwarf::DW_AT::low_pc);
            auto high_pc = iter->find(dwarf::DW_AT::high_pc);
            if (low_pc != iter->end() && high_pc != iter->end()) {
                if (pc >= low_pc->second.as_address() && pc < high_pc->second.as_address()) {
                    return *iter;
                }
            }
        }
        ++iter;
    }
    return root;
}


dwarf::line_table::iterator Debugger::get_line_from_pc(uint64_t pc) {
    auto& cu = m_dwarf.compilation_units()[0];
    auto& line_table = cu.get_line_table();
    auto iter = line_table.begin();
    while (iter != line_table.end()) {
        if (iter->address == pc) {
            return iter;
        }
        ++iter;
    }
    return line_table.end();
}


void Debugger::initialise_load_entry()
{
    auto& cu = m_dwarf.compilation_units()[0];
    auto& root = cu.root();
    auto iter = root.begin();
    while (iter != root.end()) {
        if (iter->tag == dwarf::DW_TAG::subprogram) {
            auto low_pc = iter->find(dwarf::DW_AT::low_pc);
            auto high_pc = iter->find(dwarf::DW_AT::high_pc);
            if (low_pc != iter->end() && high_pc != iter->end()) {
                auto name = iter->find(dwarf::DW_AT::name);
                if (name != iter->end()) {
                    m_load_entry[name->second.as_string()] = {low_pc->second.as_address(), high_pc->second.as_address()};
                }
            }
        }
        ++iter;
    }
}


uint64_t Debugger::offset_load_address(uint64_t addr)
{
    return addr - m_load_address;
}

void Debugger::print_source_line(
    const std::string& file_name,
    unsigned line,
    unsigned line_context_size
) {

    std::ifstream file {file_name};

    if (!file.is_open()) {
        std::cerr << "Could not open file " << file_name << std::endl;
        return;
    }

    auto start_line = line <= line_context_size ? 1 : line - line_context_size;
    auto end_line = line + line_context_size + (line < line_context_size ? line_context_size - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    while (current_line != start_line && file.get(c)) {
        if (c == '\n')
        {
            ++current_line;
        }
    }

    std::cout << (current_line==line ? "> " : " ");

    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n')
        {
            ++current_line;
            std::cout << (current_line==line ? "> " : " ");
        }
    }

    std::cout << std::endl;
}

siginfo_t Debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}




