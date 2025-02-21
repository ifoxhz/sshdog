# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/etsme/workspace/github/libbpf-bootstrap/examples/c

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/etsme/workspace/github/libbpf-bootstrap/examples/c

# Include any dependencies generated for this target.
include CMakeFiles/task_iter.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/task_iter.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/task_iter.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/task_iter.dir/flags.make

task_iter.skel.h: task_iter.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: task_iter"
	bash -c "/home/etsme/workspace/github/libbpf-bootstrap/examples/c/bpftool/bootstrap/bpftool gen skeleton /home/etsme/workspace/github/libbpf-bootstrap/examples/c/task_iter.bpf.o > /home/etsme/workspace/github/libbpf-bootstrap/examples/c/task_iter.skel.h"

task_iter.bpf.o: task_iter.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: task_iter"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/home/etsme/workspace/github/libbpf-bootstrap/examples/c/../../vmlinux.h/include/x86 -isystem /home/etsme/workspace/github/libbpf-bootstrap/examples/c/libbpf -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/task_iter.bpf.c -o /home/etsme/workspace/github/libbpf-bootstrap/examples/c/task_iter.bpf.o

CMakeFiles/task_iter.dir/task_iter.c.o: CMakeFiles/task_iter.dir/flags.make
CMakeFiles/task_iter.dir/task_iter.c.o: task_iter.c
CMakeFiles/task_iter.dir/task_iter.c.o: CMakeFiles/task_iter.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/task_iter.dir/task_iter.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/task_iter.dir/task_iter.c.o -MF CMakeFiles/task_iter.dir/task_iter.c.o.d -o CMakeFiles/task_iter.dir/task_iter.c.o -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/task_iter.c

CMakeFiles/task_iter.dir/task_iter.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/task_iter.dir/task_iter.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/etsme/workspace/github/libbpf-bootstrap/examples/c/task_iter.c > CMakeFiles/task_iter.dir/task_iter.c.i

CMakeFiles/task_iter.dir/task_iter.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/task_iter.dir/task_iter.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/etsme/workspace/github/libbpf-bootstrap/examples/c/task_iter.c -o CMakeFiles/task_iter.dir/task_iter.c.s

# Object files for target task_iter
task_iter_OBJECTS = \
"CMakeFiles/task_iter.dir/task_iter.c.o"

# External object files for target task_iter
task_iter_EXTERNAL_OBJECTS =

task_iter: CMakeFiles/task_iter.dir/task_iter.c.o
task_iter: CMakeFiles/task_iter.dir/build.make
task_iter: libbpf/libbpf.a
task_iter: CMakeFiles/task_iter.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable task_iter"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/task_iter.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/task_iter.dir/build: task_iter
.PHONY : CMakeFiles/task_iter.dir/build

CMakeFiles/task_iter.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/task_iter.dir/cmake_clean.cmake
.PHONY : CMakeFiles/task_iter.dir/clean

CMakeFiles/task_iter.dir/depend: task_iter.bpf.o
CMakeFiles/task_iter.dir/depend: task_iter.skel.h
	cd /home/etsme/workspace/github/libbpf-bootstrap/examples/c && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles/task_iter.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/task_iter.dir/depend

