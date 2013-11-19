# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion

# Include any dependencies generated for this target.
include examples/basic/CMakeFiles/basic.dir/depend.make

# Include the progress variables for this target.
include examples/basic/CMakeFiles/basic.dir/progress.make

# Include the compile flags for this target's objects.
include examples/basic/CMakeFiles/basic.dir/flags.make

examples/basic/CMakeFiles/basic.dir/basic.c.o: examples/basic/CMakeFiles/basic.dir/flags.make
examples/basic/CMakeFiles/basic.dir/basic.c.o: examples/basic/basic.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object examples/basic/CMakeFiles/basic.dir/basic.c.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/basic.dir/basic.c.o   -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic/basic.c

examples/basic/CMakeFiles/basic.dir/basic.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/basic.dir/basic.c.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic/basic.c > CMakeFiles/basic.dir/basic.c.i

examples/basic/CMakeFiles/basic.dir/basic.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/basic.dir/basic.c.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic/basic.c -o CMakeFiles/basic.dir/basic.c.s

examples/basic/CMakeFiles/basic.dir/basic.c.o.requires:
.PHONY : examples/basic/CMakeFiles/basic.dir/basic.c.o.requires

examples/basic/CMakeFiles/basic.dir/basic.c.o.provides: examples/basic/CMakeFiles/basic.dir/basic.c.o.requires
	$(MAKE) -f examples/basic/CMakeFiles/basic.dir/build.make examples/basic/CMakeFiles/basic.dir/basic.c.o.provides.build
.PHONY : examples/basic/CMakeFiles/basic.dir/basic.c.o.provides

examples/basic/CMakeFiles/basic.dir/basic.c.o.provides.build: examples/basic/CMakeFiles/basic.dir/basic.c.o

# Object files for target basic
basic_OBJECTS = \
"CMakeFiles/basic.dir/basic.c.o"

# External object files for target basic
basic_EXTERNAL_OBJECTS =

examples/basic/basic: examples/basic/CMakeFiles/basic.dir/basic.c.o
examples/basic/basic: src/onion/handlers/libonion_handlers.so
examples/basic/basic: src/onion/libonion.so
examples/basic/basic: /usr/lib/x86_64-linux-gnu/librt.so
examples/basic/basic: /usr/lib/x86_64-linux-gnu/libxml2.so
examples/basic/basic: examples/basic/CMakeFiles/basic.dir/build.make
examples/basic/basic: examples/basic/CMakeFiles/basic.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable basic"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/basic.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
examples/basic/CMakeFiles/basic.dir/build: examples/basic/basic
.PHONY : examples/basic/CMakeFiles/basic.dir/build

examples/basic/CMakeFiles/basic.dir/requires: examples/basic/CMakeFiles/basic.dir/basic.c.o.requires
.PHONY : examples/basic/CMakeFiles/basic.dir/requires

examples/basic/CMakeFiles/basic.dir/clean:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic && $(CMAKE_COMMAND) -P CMakeFiles/basic.dir/cmake_clean.cmake
.PHONY : examples/basic/CMakeFiles/basic.dir/clean

examples/basic/CMakeFiles/basic.dir/depend:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/basic/CMakeFiles/basic.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/basic/CMakeFiles/basic.dir/depend

