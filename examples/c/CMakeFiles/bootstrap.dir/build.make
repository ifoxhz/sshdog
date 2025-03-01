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
include CMakeFiles/bootstrap.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/bootstrap.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/bootstrap.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bootstrap.dir/flags.make

bootstrap.skel.h: bootstrap.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: bootstrap"
	bash -c "/home/etsme/workspace/github/libbpf-bootstrap/examples/c/bpftool/bootstrap/bpftool gen skeleton /home/etsme/workspace/github/libbpf-bootstrap/examples/c/bootstrap.bpf.o > /home/etsme/workspace/github/libbpf-bootstrap/examples/c/bootstrap.skel.h"

bootstrap.bpf.o: bootstrap.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: bootstrap"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/home/etsme/workspace/github/libbpf-bootstrap/examples/c/../../vmlinux.h/include/x86 -isystem /home/etsme/workspace/github/libbpf-bootstrap/examples/c/libbpf -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/bootstrap.bpf.c -o /home/etsme/workspace/github/libbpf-bootstrap/examples/c/bootstrap.bpf.o

CMakeFiles/bootstrap.dir/bootstrap.c.o: CMakeFiles/bootstrap.dir/flags.make
CMakeFiles/bootstrap.dir/bootstrap.c.o: bootstrap.c
CMakeFiles/bootstrap.dir/bootstrap.c.o: CMakeFiles/bootstrap.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/bootstrap.dir/bootstrap.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/bootstrap.dir/bootstrap.c.o -MF CMakeFiles/bootstrap.dir/bootstrap.c.o.d -o CMakeFiles/bootstrap.dir/bootstrap.c.o -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/bootstrap.c

CMakeFiles/bootstrap.dir/bootstrap.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bootstrap.dir/bootstrap.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/etsme/workspace/github/libbpf-bootstrap/examples/c/bootstrap.c > CMakeFiles/bootstrap.dir/bootstrap.c.i

CMakeFiles/bootstrap.dir/bootstrap.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bootstrap.dir/bootstrap.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/etsme/workspace/github/libbpf-bootstrap/examples/c/bootstrap.c -o CMakeFiles/bootstrap.dir/bootstrap.c.s

# Object files for target bootstrap
bootstrap_OBJECTS = \
"CMakeFiles/bootstrap.dir/bootstrap.c.o"

# External object files for target bootstrap
bootstrap_EXTERNAL_OBJECTS =

bootstrap: CMakeFiles/bootstrap.dir/bootstrap.c.o
bootstrap: CMakeFiles/bootstrap.dir/build.make
bootstrap: libbpf/libbpf.a
bootstrap: CMakeFiles/bootstrap.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable bootstrap"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bootstrap.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bootstrap.dir/build: bootstrap
.PHONY : CMakeFiles/bootstrap.dir/build

CMakeFiles/bootstrap.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bootstrap.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bootstrap.dir/clean

CMakeFiles/bootstrap.dir/depend: bootstrap.bpf.o
CMakeFiles/bootstrap.dir/depend: bootstrap.skel.h
	cd /home/etsme/workspace/github/libbpf-bootstrap/examples/c && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles/bootstrap.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bootstrap.dir/depend

