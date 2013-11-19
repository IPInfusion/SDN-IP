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
include tests/05-sessions/CMakeFiles/sessions.dir/depend.make

# Include the progress variables for this target.
include tests/05-sessions/CMakeFiles/sessions.dir/progress.make

# Include the compile flags for this target's objects.
include tests/05-sessions/CMakeFiles/sessions.dir/flags.make

tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o: tests/05-sessions/CMakeFiles/sessions.dir/flags.make
tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o: tests/05-sessions/sessions.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/sessions.dir/sessions.c.o   -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions/sessions.c

tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sessions.dir/sessions.c.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions/sessions.c > CMakeFiles/sessions.dir/sessions.c.i

tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sessions.dir/sessions.c.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions/sessions.c -o CMakeFiles/sessions.dir/sessions.c.s

tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.requires:
.PHONY : tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.requires

tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.provides: tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.requires
	$(MAKE) -f tests/05-sessions/CMakeFiles/sessions.dir/build.make tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.provides.build
.PHONY : tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.provides

tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.provides.build: tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o

# Object files for target sessions
sessions_OBJECTS = \
"CMakeFiles/sessions.dir/sessions.c.o"

# External object files for target sessions
sessions_EXTERNAL_OBJECTS =

tests/05-sessions/sessions: tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o
tests/05-sessions/sessions: src/onion/libonion.so
tests/05-sessions/sessions: src/onion/handlers/libonion_handlers.so
tests/05-sessions/sessions: src/onion/libonion.so
tests/05-sessions/sessions: /usr/lib/x86_64-linux-gnu/librt.so
tests/05-sessions/sessions: /usr/lib/x86_64-linux-gnu/libxml2.so
tests/05-sessions/sessions: tests/05-sessions/CMakeFiles/sessions.dir/build.make
tests/05-sessions/sessions: tests/05-sessions/CMakeFiles/sessions.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable sessions"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sessions.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/05-sessions/CMakeFiles/sessions.dir/build: tests/05-sessions/sessions
.PHONY : tests/05-sessions/CMakeFiles/sessions.dir/build

tests/05-sessions/CMakeFiles/sessions.dir/requires: tests/05-sessions/CMakeFiles/sessions.dir/sessions.c.o.requires
.PHONY : tests/05-sessions/CMakeFiles/sessions.dir/requires

tests/05-sessions/CMakeFiles/sessions.dir/clean:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions && $(CMAKE_COMMAND) -P CMakeFiles/sessions.dir/cmake_clean.cmake
.PHONY : tests/05-sessions/CMakeFiles/sessions.dir/clean

tests/05-sessions/CMakeFiles/sessions.dir/depend:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tests/05-sessions/CMakeFiles/sessions.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/05-sessions/CMakeFiles/sessions.dir/depend

