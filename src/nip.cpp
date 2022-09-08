
#include "linenoise.h"




class breakpoint 
{
    public:
        breakpoint(pid_t pid, std::intptr_t addr) : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}

        void enable();
        void disable();

        bool is_enabled() const -> bool { return m_enabled; }
        auto get_address() const -> std::intptr_t { return m_addr; }

    private:
        pid_t m_pid;
        std::intptr_t m_addr;
        bool m_enabled;
        std::uint8_t m_saved_data; // original data at breakpoint address
}

void breakpoint::enable()
{
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    m_saved_data = static_cast<std::uint8_t>(data & 0xff); // save the original data
    std::uint64_t int3 = 0xcc;
    std::uint64_t data_with_int3 = ((data & ~0xff) | int3); // replace the original data with int3
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);
    m_enabled = true;
}

void breakpoint::disable()
{
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    auto restored_data = ((data & ~0xff) | m_saved_data);
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);
    m_enabled = false;
}

class debugger 
{

    public:
        debugger(std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

        void run();
        void set_breakpoint_at_address(std::intptr_t addr);

    private:
        void handle_command(const std::string& line);
        void continue_execution();


        std::string m_prog_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;

}

void debugger::set_breakpoint_at_address(std::intptr_t addr)
{
    std::cout << "Set breakpoint at address: " << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints.insert({addr, bp});
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


void debugger::handle_command(const std::string& line)
{
    auto args = split(line, ' ');
    auto command = args[0];

    if(is_prefix(command, "continue"))
    {
        continue_execution();
    }
    else if(cis_prefix(command, "break"))
    {
        if (args.size() != 2)
        {
            std::cerr << "usage: break <location>" << std::endl;
            std::string addr = {args[1], std::size_t(2)};
            set_breakpoint_at_address(std::stol(addr, 0, 16));
        }
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
    }
}


void debugger::run()
{
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    char* line = nullptr;
    while((line = linenoise("nip> ")) != nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

int main(int argc, char* argv[])
{
    if(argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return -1;
    }

    auto prog = argv[1];

    // fork() causes our program to split into two processes, one parent and one child.
    auto pid = fork();

    if(pid == 0)
    {
        // Child process, replace it with the program we want to debug.
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(prog, prog, nullptr);
    }
    else
    {
        // Parent process
        std::cout << "Started debugging " << prog << " with pid " << pid << std::endl;
        

        debugger dbg{prog, pid};
        dbg.run();
    }
}