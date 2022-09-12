
#include "linenoise.h"

enum class reg {
    rax, rbx, 
    rcx, rdx,
    rsi, rdi,
    rbp, rsp,
    r8, r9, r10, r11, r12, r13, r14, r15,
    rip, rflags,
    cs, ds, es, fs, gs, ss,
    orig_rax, fs_base, gs_base
};

constexpr std::size_t reg_count = 27;

struct reg_info {
    reg r;
    int dwarf_r;
    std::string name;
};


const std::array<reg_info, reg_count> g_register_descriptors {{
    { reg::r15, 15, "r15"},
    { reg::r14, 14, "r14"},
    { reg::r13, 13, "r13"},
    { reg::r12, 12, "r12"},
    { reg::rbp, 6, "rbp"},
    { reg::rbx, 3, "rbx"},
    { reg::r11, 11, "r11"},
    { reg::r10, 10, "r10"},
    { reg::r9, 9, "r9"},
    { reg::r8, 8, "r8"},
    { reg::rax, 0, "rax"},
    { reg::rcx, 2, "rcx"},
    { reg::rdx, 1, "rdx"},
    { reg::rsi, 4, "rsi"},
    { reg::rdi, 5, "rdi"},
    { reg::orig_rax, -1, "orig_rax"},
    { reg::rip, -1, "rip"},
    { reg::cs, 51, "cs"},
    { reg::eflags, 49, "eflags"},
    { reg::rsp, 7, "rsp"},
    { reg::ss, 52, "ss"},
    { reg::fs_base, 58, "fs_base"},
    { reg::gs_base, 59, "gs_base"},
    { reg::ds, 53, "ds"},
    { reg::es, 50, "es"},
    { reg::fs, 54, "fs"},
    { reg::gs, 55, "gs"}
}};

uint64_t get_register_value(pid_t pid, reg r)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [r](const reg_info& ri) {
        return ri.r == r;
    });

    return *(reinterpret_cast<uint64_t*>(&regs) + (it - g_register_descriptors.begin()));
}

void set_register_value(pid_t pid, reg r, uint64_t value)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [r](const reg_info& ri) {
        return ri.r == r;
    });

    *(reinterpret_cast<uint64_t*>(&regs) + (it - g_register_descriptors.begin())) = value;

    ptrace(PTRACE_SETREGS, pid, 0, &regs);
}

uint64_t get_register_value_from_dwarf_register(pid_t pid, int dwarf_r)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [dwarf_r](const reg_info& ri) {
        return ri.dwarf_r == dwarf_r;
    });

    if (it == g_register_descriptors.end())
        throw std::out_of_range("Invalid dwarf register");

    return get_register_value(pid, it->r);
}

std::string get_register_name(reg r)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [r](const reg_info& ri) {
        return ri.r == r;
    });

    return it->name;
}

reg get_register_from_name(const std::string& name)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(), [name](const reg_info& ri) {
        return ri.name == name;
    });

    return it->r;
}



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
};

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

};





uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}


uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

void debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}


void debugger::step_over_breakpoint() {
    // - 1 because execution will go past the breakpoint
    auto possible_breakpoint_location = get_pc() - 1;

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


void debugger::dump_registers()
{
    for(const auto& rd : g_register_descriptors)
    {
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;    
    }
}



void debugger::set_breakpoint_at_address(std::intptr_t addr)
{
    std::cout << "Set breakpoint at address: " << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints.insert({addr, bp});
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
    else if(is_prefix(command, "register"))
    {
        if(is_prefix(args[1]), "dump")
        {
            dump_registers();
        }
        else if(is_prefix(args[1], "read"))
        {
            if(args.size() != 3)
            {
                std::cerr << "usage: register read <register name>" << std::endl;
                return;
            }

            auto reg_name = args[2];
            auto reg = get_register_from_name(reg_name);
            std::cout << reg_name << " = " << get_register_value(m_pid, reg) << std::endl;
        }
        else if(is_prefix(args[1], "write"))
        {
            if(args.size() != 4)
            {
                std::cerr << "usage: register write <register name> <value>" << std::endl;
                return;
            }

            auto reg_name = args[2];
            auto reg = get_register_from_name(reg_name);
            auto value = std::stol(args[3], 0, 16);
            set_register_value(m_pid, reg, value);
        }
    }
    else if(is_prefix(command, "memory"))
    {
        std::string addr {args[2], 2}; //assume 0xADDRESS

        if (is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2}; //assume 0xVAL
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
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
        personality(ADDR_NO_RANDOMIZE);
        execute_debuggee(prog);
    }
    else
    {
        // Parent process
        std::cout << "Started debugging " << prog << " with pid " << pid << std::endl;
        

        debugger dbg{prog, pid};
        dbg.run();
    }
}