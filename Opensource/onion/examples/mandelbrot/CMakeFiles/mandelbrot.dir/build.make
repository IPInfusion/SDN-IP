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
include examples/mandelbrot/CMakeFiles/mandelbrot.dir/depend.make

# Include the progress variables for this target.
include examples/mandelbrot/CMakeFiles/mandelbrot.dir/progress.make

# Include the compile flags for this target's objects.
include examples/mandelbrot/CMakeFiles/mandelbrot.dir/flags.make

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o: examples/mandelbrot/CMakeFiles/mandelbrot.dir/flags.make
examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o: examples/mandelbrot/mandelbrot.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && /usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandelbrot.cpp

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/mandelbrot.dir/mandelbrot.cpp.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandelbrot.cpp > CMakeFiles/mandelbrot.dir/mandelbrot.cpp.i

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/mandelbrot.dir/mandelbrot.cpp.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && /usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandelbrot.cpp -o CMakeFiles/mandelbrot.dir/mandelbrot.cpp.s

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.requires:
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.requires

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.provides: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.requires
	$(MAKE) -f examples/mandelbrot/CMakeFiles/mandelbrot.dir/build.make examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.provides.build
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.provides

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.provides.build: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o: examples/mandelbrot/CMakeFiles/mandelbrot.dir/flags.make
examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o: examples/mandelbrot/mandel_html.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/mandelbrot.dir/mandel_html.c.o   -c /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandel_html.c

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/mandelbrot.dir/mandel_html.c.i"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandel_html.c > CMakeFiles/mandelbrot.dir/mandel_html.c.i

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/mandelbrot.dir/mandel_html.c.s"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandel_html.c -o CMakeFiles/mandelbrot.dir/mandel_html.c.s

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.requires:
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.requires

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.provides: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.requires
	$(MAKE) -f examples/mandelbrot/CMakeFiles/mandelbrot.dir/build.make examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.provides.build
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.provides

examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.provides.build: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o

examples/mandelbrot/mandel_html.c: tools/otemplate/otemplate
examples/mandelbrot/mandel_html.c: examples/mandelbrot/mandel.html
	$(CMAKE_COMMAND) -E cmake_progress_report /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/CMakeFiles $(CMAKE_PROGRESS_3)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold "Generating mandel_html.c"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && ../../tools/otemplate/otemplate /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandel.html /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/mandel_html.c

# Object files for target mandelbrot
mandelbrot_OBJECTS = \
"CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o" \
"CMakeFiles/mandelbrot.dir/mandel_html.c.o"

# External object files for target mandelbrot
mandelbrot_EXTERNAL_OBJECTS =

examples/mandelbrot/mandelbrot: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o
examples/mandelbrot/mandelbrot: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o
examples/mandelbrot/mandelbrot: src/onion/libonion_static.a
examples/mandelbrot/mandelbrot: src/onion/extras/libonion_extras.a
examples/mandelbrot/mandelbrot: /usr/lib/x86_64-linux-gnu/librt.so
examples/mandelbrot/mandelbrot: /usr/lib/x86_64-linux-gnu/libpng.so
examples/mandelbrot/mandelbrot: examples/mandelbrot/CMakeFiles/mandelbrot.dir/build.make
examples/mandelbrot/mandelbrot: examples/mandelbrot/CMakeFiles/mandelbrot.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX executable mandelbrot"
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/mandelbrot.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
examples/mandelbrot/CMakeFiles/mandelbrot.dir/build: examples/mandelbrot/mandelbrot
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/build

examples/mandelbrot/CMakeFiles/mandelbrot.dir/requires: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandelbrot.cpp.o.requires
examples/mandelbrot/CMakeFiles/mandelbrot.dir/requires: examples/mandelbrot/CMakeFiles/mandelbrot.dir/mandel_html.c.o.requires
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/requires

examples/mandelbrot/CMakeFiles/mandelbrot.dir/clean:
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot && $(CMAKE_COMMAND) -P CMakeFiles/mandelbrot.dir/cmake_clean.cmake
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/clean

examples/mandelbrot/CMakeFiles/mandelbrot.dir/depend: examples/mandelbrot/mandel_html.c
	cd /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot /home/tetsuya/work/ON.Lab/BGP_SDN_without_onion/BGP-SDN/opensource/onion/examples/mandelbrot/CMakeFiles/mandelbrot.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/mandelbrot/CMakeFiles/mandelbrot.dir/depend

