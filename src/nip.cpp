#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "linenoise.h"
#include "Debugger.hpp"
#include "registers.hpp"


int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
        //we're in the child process
        //execute debugee
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(prog, prog, nullptr);

    }
    else if (pid >= 1)  {
        //we're in the parent process
        //execute debugger
        std::cout << "Started debugging process with process: " << pid << std::endl;

        Debugger debugger{prog, pid};
    }
}
