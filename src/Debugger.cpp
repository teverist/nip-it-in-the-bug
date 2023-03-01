
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
    else {
        std::cerr << "Unknown command\n";
    }
}


void debugger::continue_execution() {
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
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