
#include "linenoise.h"


class debugger 
{

    public:
        debugger(std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

        void run();

    private:
        void handle_command(const std::string& line);
        void continue_execution();


        std::string m_prog_name;
        pid_t m_pid;

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