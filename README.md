# A Simple Linux Debugger for x86 architecture
---


## Introduction

This is a simple Linux debugger for x86 architecture. It is written in C++ and uses the ptrace system call to debug the target process. It is a work in progress and is not yet complete. It is currently capable of debugging a single process and setting breakpoints. It is also capable of single stepping and printing the registers and memory.

Two dependencies are required for this project: Linenoise and libelfin. Linenoise is a simple readline implementation and libelfin is a library for parsing DWARF files. Both of these dependencies are included in the repository.

