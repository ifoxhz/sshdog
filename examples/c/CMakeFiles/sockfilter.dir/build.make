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
include CMakeFiles/sockfilter.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/sockfilter.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/sockfilter.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sockfilter.dir/flags.make

sockfilter.skel.h: sockfilter.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: sockfilter"
	bash -c "/home/etsme/workspace/github/libbpf-bootstrap/examples/c/bpftool/bootstrap/bpftool gen skeleton /home/etsme/workspace/github/libbpf-bootstrap/examples/c/sockfilter.bpf.o > /home/etsme/workspace/github/libbpf-bootstrap/examples/c/sockfilter.skel.h"

sockfilter.bpf.o: sockfilter.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: sockfilter"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/home/etsme/workspace/github/libbpf-bootstrap/examples/c/../../vmlinux.h/include/x86 -isystem /home/etsme/workspace/github/libbpf-bootstrap/examples/c/libbpf -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/sockfilter.bpf.c -o /home/etsme/workspace/github/libbpf-bootstrap/examples/c/sockfilter.bpf.o

CMakeFiles/sockfilter.dir/sockfilter.c.o: CMakeFiles/sockfilter.dir/flags.make
CMakeFiles/sockfilter.dir/sockfilter.c.o: sockfilter.c
CMakeFiles/sockfilter.dir/sockfilter.c.o: CMakeFiles/sockfilter.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/sockfilter.dir/sockfilter.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/sockfilter.dir/sockfilter.c.o -MF CMakeFiles/sockfilter.dir/sockfilter.c.o.d -o CMakeFiles/sockfilter.dir/sockfilter.c.o -c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/sockfilter.c

CMakeFiles/sockfilter.dir/sockfilter.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sockfilter.dir/sockfilter.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/etsme/workspace/github/libbpf-bootstrap/examples/c/sockfilter.c > CMakeFiles/sockfilter.dir/sockfilter.c.i

CMakeFiles/sockfilter.dir/sockfilter.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sockfilter.dir/sockfilter.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/etsme/workspace/github/libbpf-bootstrap/examples/c/sockfilter.c -o CMakeFiles/sockfilter.dir/sockfilter.c.s

# Object files for target sockfilter
sockfilter_OBJECTS = \
"CMakeFiles/sockfilter.dir/sockfilter.c.o"

# External object files for target sockfilter
sockfilter_EXTERNAL_OBJECTS =

sockfilter: CMakeFiles/sockfilter.dir/sockfilter.c.o
sockfilter: CMakeFiles/sockfilter.dir/build.make
sockfilter: libbpf/libbpf.a
sockfilter: CMakeFiles/sockfilter.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable sockfilter"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sockfilter.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sockfilter.dir/build: sockfilter
.PHONY : CMakeFiles/sockfilter.dir/build

CMakeFiles/sockfilter.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sockfilter.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sockfilter.dir/clean

CMakeFiles/sockfilter.dir/depend: sockfilter.bpf.o
CMakeFiles/sockfilter.dir/depend: sockfilter.skel.h
	cd /home/etsme/workspace/github/libbpf-bootstrap/examples/c && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c /home/etsme/workspace/github/libbpf-bootstrap/examples/c/CMakeFiles/sockfilter.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sockfilter.dir/depend

