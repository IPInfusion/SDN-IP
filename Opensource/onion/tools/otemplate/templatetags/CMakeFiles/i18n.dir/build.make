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
include tools/otemplate/templatetags/CMakeFiles/i18n.dir/depend.make

# Include the progress variables for this target.
include tools/otemplate/templatetags/CMakeFiles/i18n.dir/progress.make

# Include the compile flags for this target's objects.
include tools/otemplate/templatetags/CMakeFiles/i18n.dir/flags.make

tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o: tools/otemplate/templatetags/CMakeFiles/i18n.dir/flags.make
tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o: tools/otemplate/templatetags/i18n.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/i18n.dir/i18n.c.o   -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags/i18n.c

tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/i18n.dir/i18n.c.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags/i18n.c > CMakeFiles/i18n.dir/i18n.c.i

tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/i18n.dir/i18n.c.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags/i18n.c -o CMakeFiles/i18n.dir/i18n.c.s

tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.requires:
.PHONY : tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.requires

tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.provides: tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.requires
	$(MAKE) -f tools/otemplate/templatetags/CMakeFiles/i18n.dir/build.make tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.provides.build
.PHONY : tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.provides

tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.provides.build: tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o

# Object files for target i18n
i18n_OBJECTS = \
"CMakeFiles/i18n.dir/i18n.c.o"

# External object files for target i18n
i18n_EXTERNAL_OBJECTS =

tools/otemplate/templatetags/libi18n.so: tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o
tools/otemplate/templatetags/libi18n.so: tools/otemplate/templatetags/CMakeFiles/i18n.dir/build.make
tools/otemplate/templatetags/libi18n.so: tools/otemplate/templatetags/CMakeFiles/i18n.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C shared library libi18n.so"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/i18n.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tools/otemplate/templatetags/CMakeFiles/i18n.dir/build: tools/otemplate/templatetags/libi18n.so
.PHONY : tools/otemplate/templatetags/CMakeFiles/i18n.dir/build

tools/otemplate/templatetags/CMakeFiles/i18n.dir/requires: tools/otemplate/templatetags/CMakeFiles/i18n.dir/i18n.c.o.requires
.PHONY : tools/otemplate/templatetags/CMakeFiles/i18n.dir/requires

tools/otemplate/templatetags/CMakeFiles/i18n.dir/clean:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags && $(CMAKE_COMMAND) -P CMakeFiles/i18n.dir/cmake_clean.cmake
.PHONY : tools/otemplate/templatetags/CMakeFiles/i18n.dir/clean

tools/otemplate/templatetags/CMakeFiles/i18n.dir/depend:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/tools/otemplate/templatetags/CMakeFiles/i18n.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tools/otemplate/templatetags/CMakeFiles/i18n.dir/depend

