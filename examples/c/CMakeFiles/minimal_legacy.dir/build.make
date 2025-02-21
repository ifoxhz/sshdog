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
include CMakeFiles/minimal_legacy.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/minimal_legacy.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/minimal_legacy.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/minimal_legacy.dir/flags.make

minimal_legacy.skel.h: minimal_legacy.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: minimal_legacy"
	bash -c "/home/etsme/workspace/github/libbpf-bootstrap/examples/c/bpftool/bootstrap/bpftool gen skeleton /home/etsme/workspace/github/libbpf-bootstrap/examples/c/minimal_legacy.bpf.o > /home/etsme/workspace/github/libbpf-bootstrap/examples/c/minimal_legacy.skel.h"

minimal_legacy.bpf.o: minimal_legacy.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: minimal_legacy"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/home/etsme/workspace/github/libbpf-bootstrap/examples/c/../../vmlinux.h/include/x86 -isystem /home/etsme/workspace/github/libbpf-bootstrap/examples/c/libbpf -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/minimal_legacy.bpf.c -o /home/etsme/workspace/github/libbpf-bootstrap/examples/c/minimal_legacy.bpf.o

CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o: CMakeFiles/minimal_legacy.dir/flags.make
CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o: minimal_legacy.c
CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o: CMakeFiles/minimal_legacy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o -MF CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o.d -o CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/minimal_legacy.c

CMakeFiles/minimal_legacy.dir/minimal_legacy.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/minimal_legacy.dir/minimal_legacy.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/etsme/workspace/github/libbpf-bootstrap/examples/c/minimal_legacy.c > CMakeFiles/minimal_legacy.dir/minimal_legacy.c.i

CMakeFiles/minimal_legacy.dir/minimal_legacy.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/minimal_legacy.dir/minimal_legacy.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/etsme/workspace/github/libbpf-bootstrap/examples/c/minimal_legacy.c -o CMakeFiles/minimal_legacy.dir/minimal_legacy.c.s

# Object files for target minimal_legacy
minimal_legacy_OBJECTS = \
"CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o"

# External object files for target minimal_legacy
minimal_legacy_EXTERNAL_OBJECTS =

minimal_legacy: CMakeFiles/minimal_legacy.dir/minimal_legacy.c.o
minimal_legacy: CMakeFiles/minimal_legacy.dir/build.make
minimal_legacy: libbpf/libbpf.a
minimal_legacy: CMakeFiles/minimal_legacy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable minimal_legacy"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/minimal_legacy.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/minimal_legacy.dir/build: minimal_legacy
.PHONY : CMakeFiles/minimal_legacy.dir/build

CMakeFiles/minimal_legacy.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/minimal_legacy.dir/cmake_clean.cmake
.PHONY : CMakeFiles/minimal_legacy.dir/clean

CMakeFiles/minimal_legacy.dir/depend: minimal_legacy.bpf.o
CMakeFiles/minimal_legacy.dir/depend: minimal_legacy.skel.h
	cd /home/etsme/workspace/github/libbpf-bootstrap/examples/c && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles/minimal_legacy.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/minimal_legacy.dir/depend

