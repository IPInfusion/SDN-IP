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
include tests/01-internal/CMakeFiles/05-server.dir/depend.make

# Include the progress variables for this target.
include tests/01-internal/CMakeFiles/05-server.dir/progress.make

# Include the compile flags for this target's objects.
include tests/01-internal/CMakeFiles/05-server.dir/flags.make

tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o: tests/01-internal/CMakeFiles/05-server.dir/flags.make
tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o: tests/01-internal/05-server.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/05-server.dir/05-server.c.o   -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal/05-server.c

tests/01-internal/CMakeFiles/05-server.dir/05-server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/05-server.dir/05-server.c.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal/05-server.c > CMakeFiles/05-server.dir/05-server.c.i

tests/01-internal/CMakeFiles/05-server.dir/05-server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/05-server.dir/05-server.c.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal/05-server.c -o CMakeFiles/05-server.dir/05-server.c.s

tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.requires:
.PHONY : tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.requires

tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.provides: tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.requires
	$(MAKE) -f tests/01-internal/CMakeFiles/05-server.dir/build.make tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.provides.build
.PHONY : tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.provides

tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.provides.build: tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o

# Object files for target 05-server
05__server_OBJECTS = \
"CMakeFiles/05-server.dir/05-server.c.o"

# External object files for target 05-server
05__server_EXTERNAL_OBJECTS =

tests/01-internal/05-server: tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o
tests/01-internal/05-server: src/onion/handlers/libonion_handlers.so
tests/01-internal/05-server: src/onion/libonion.so
tests/01-internal/05-server: /usr/lib/x86_64-linux-gnu/librt.so
tests/01-internal/05-server: /usr/lib/x86_64-linux-gnu/libxml2.so
tests/01-internal/05-server: tests/01-internal/CMakeFiles/05-server.dir/build.make
tests/01-internal/05-server: tests/01-internal/CMakeFiles/05-server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable 05-server"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/05-server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/01-internal/CMakeFiles/05-server.dir/build: tests/01-internal/05-server
.PHONY : tests/01-internal/CMakeFiles/05-server.dir/build

tests/01-internal/CMakeFiles/05-server.dir/requires: tests/01-internal/CMakeFiles/05-server.dir/05-server.c.o.requires
.PHONY : tests/01-internal/CMakeFiles/05-server.dir/requires

tests/01-internal/CMakeFiles/05-server.dir/clean:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal && $(CMAKE_COMMAND) -P CMakeFiles/05-server.dir/cmake_clean.cmake
.PHONY : tests/01-internal/CMakeFiles/05-server.dir/clean

tests/01-internal/CMakeFiles/05-server.dir/depend:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/01-internal/CMakeFiles/05-server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/01-internal/CMakeFiles/05-server.dir/depend

