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
include examples/ofileserver/CMakeFiles/ofileserver.dir/depend.make

# Include the progress variables for this target.
include examples/ofileserver/CMakeFiles/ofileserver.dir/progress.make

# Include the compile flags for this target's objects.
include examples/ofileserver/CMakeFiles/ofileserver.dir/flags.make

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o: examples/ofileserver/CMakeFiles/ofileserver.dir/flags.make
examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o: examples/ofileserver/fileserver.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/ofileserver.dir/fileserver.c.o   -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver.c

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ofileserver.dir/fileserver.c.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver.c > CMakeFiles/ofileserver.dir/fileserver.c.i

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ofileserver.dir/fileserver.c.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver.c -o CMakeFiles/ofileserver.dir/fileserver.c.s

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.requires:
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.requires

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.provides: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.requires
	$(MAKE) -f examples/ofileserver/CMakeFiles/ofileserver.dir/build.make examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.provides.build
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.provides

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.provides.build: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o: examples/ofileserver/CMakeFiles/ofileserver.dir/flags.make
examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o: examples/ofileserver/fileserver_html.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/ofileserver.dir/fileserver_html.c.o   -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver_html.c

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ofileserver.dir/fileserver_html.c.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver_html.c > CMakeFiles/ofileserver.dir/fileserver_html.c.i

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ofileserver.dir/fileserver_html.c.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver_html.c -o CMakeFiles/ofileserver.dir/fileserver_html.c.s

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.requires:
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.requires

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.provides: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.requires
	$(MAKE) -f examples/ofileserver/CMakeFiles/ofileserver.dir/build.make examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.provides.build
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.provides

examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.provides.build: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o

examples/ofileserver/fileserver_html.c: tools/otemplate/otemplate
examples/ofileserver/fileserver_html.c: examples/ofileserver/fileserver.html
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_3)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold "Generating fileserver_html.c"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && ../../tools/otemplate/otemplate /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver.html /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/fileserver_html.c

# Object files for target ofileserver
ofileserver_OBJECTS = \
"CMakeFiles/ofileserver.dir/fileserver.c.o" \
"CMakeFiles/ofileserver.dir/fileserver_html.c.o"

# External object files for target ofileserver
ofileserver_EXTERNAL_OBJECTS =

examples/ofileserver/ofileserver: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o
examples/ofileserver/ofileserver: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o
examples/ofileserver/ofileserver: src/onion/handlers/libonion_handlers_static.a
examples/ofileserver/ofileserver: src/onion/libonion_static.a
examples/ofileserver/ofileserver: /usr/lib/x86_64-linux-gnu/libxml2.so
examples/ofileserver/ofileserver: /usr/lib/x86_64-linux-gnu/librt.so
examples/ofileserver/ofileserver: examples/ofileserver/CMakeFiles/ofileserver.dir/build.make
examples/ofileserver/ofileserver: examples/ofileserver/CMakeFiles/ofileserver.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable ofileserver"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ofileserver.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
examples/ofileserver/CMakeFiles/ofileserver.dir/build: examples/ofileserver/ofileserver
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/build

examples/ofileserver/CMakeFiles/ofileserver.dir/requires: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver.c.o.requires
examples/ofileserver/CMakeFiles/ofileserver.dir/requires: examples/ofileserver/CMakeFiles/ofileserver.dir/fileserver_html.c.o.requires
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/requires

examples/ofileserver/CMakeFiles/ofileserver.dir/clean:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver && $(CMAKE_COMMAND) -P CMakeFiles/ofileserver.dir/cmake_clean.cmake
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/clean

examples/ofileserver/CMakeFiles/ofileserver.dir/depend: examples/ofileserver/fileserver_html.c
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/ofileserver/CMakeFiles/ofileserver.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/ofileserver/CMakeFiles/ofileserver.dir/depend

