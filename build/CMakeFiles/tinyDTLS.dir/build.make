# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


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

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build"

# Include any dependencies generated for this target.
include CMakeFiles/tinyDTLS.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/tinyDTLS.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/tinyDTLS.dir/flags.make

CMakeFiles/tinyDTLS.dir/dtls.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/dtls.c.o: ../dtls.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/tinyDTLS.dir/dtls.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/dtls.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls.c"

CMakeFiles/tinyDTLS.dir/dtls.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/dtls.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls.c" > CMakeFiles/tinyDTLS.dir/dtls.c.i

CMakeFiles/tinyDTLS.dir/dtls.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/dtls.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls.c" -o CMakeFiles/tinyDTLS.dir/dtls.c.s

CMakeFiles/tinyDTLS.dir/dtls.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/dtls.c.o.requires

CMakeFiles/tinyDTLS.dir/dtls.c.o.provides: CMakeFiles/tinyDTLS.dir/dtls.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/dtls.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/dtls.c.o.provides

CMakeFiles/tinyDTLS.dir/dtls.c.o.provides.build: CMakeFiles/tinyDTLS.dir/dtls.c.o


CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o: ../dtls-crypto.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-crypto.c"

CMakeFiles/tinyDTLS.dir/dtls-crypto.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/dtls-crypto.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-crypto.c" > CMakeFiles/tinyDTLS.dir/dtls-crypto.c.i

CMakeFiles/tinyDTLS.dir/dtls-crypto.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/dtls-crypto.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-crypto.c" -o CMakeFiles/tinyDTLS.dir/dtls-crypto.c.s

CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.requires

CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.provides: CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.provides

CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.provides.build: CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o


CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o: ../dtls-ccm.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-ccm.c"

CMakeFiles/tinyDTLS.dir/dtls-ccm.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/dtls-ccm.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-ccm.c" > CMakeFiles/tinyDTLS.dir/dtls-ccm.c.i

CMakeFiles/tinyDTLS.dir/dtls-ccm.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/dtls-ccm.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-ccm.c" -o CMakeFiles/tinyDTLS.dir/dtls-ccm.c.s

CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.requires

CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.provides: CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.provides

CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.provides.build: CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o


CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o: ../dtls-hmac.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-hmac.c"

CMakeFiles/tinyDTLS.dir/dtls-hmac.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/dtls-hmac.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-hmac.c" > CMakeFiles/tinyDTLS.dir/dtls-hmac.c.i

CMakeFiles/tinyDTLS.dir/dtls-hmac.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/dtls-hmac.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-hmac.c" -o CMakeFiles/tinyDTLS.dir/dtls-hmac.c.s

CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.requires

CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.provides: CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.provides

CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.provides.build: CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o


CMakeFiles/tinyDTLS.dir/netq.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/netq.c.o: ../netq.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/tinyDTLS.dir/netq.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/netq.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/netq.c"

CMakeFiles/tinyDTLS.dir/netq.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/netq.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/netq.c" > CMakeFiles/tinyDTLS.dir/netq.c.i

CMakeFiles/tinyDTLS.dir/netq.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/netq.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/netq.c" -o CMakeFiles/tinyDTLS.dir/netq.c.s

CMakeFiles/tinyDTLS.dir/netq.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/netq.c.o.requires

CMakeFiles/tinyDTLS.dir/netq.c.o.provides: CMakeFiles/tinyDTLS.dir/netq.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/netq.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/netq.c.o.provides

CMakeFiles/tinyDTLS.dir/netq.c.o.provides.build: CMakeFiles/tinyDTLS.dir/netq.c.o


CMakeFiles/tinyDTLS.dir/dtls-peer.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/dtls-peer.c.o: ../dtls-peer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/tinyDTLS.dir/dtls-peer.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/dtls-peer.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-peer.c"

CMakeFiles/tinyDTLS.dir/dtls-peer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/dtls-peer.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-peer.c" > CMakeFiles/tinyDTLS.dir/dtls-peer.c.i

CMakeFiles/tinyDTLS.dir/dtls-peer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/dtls-peer.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-peer.c" -o CMakeFiles/tinyDTLS.dir/dtls-peer.c.s

CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.requires

CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.provides: CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.provides

CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.provides.build: CMakeFiles/tinyDTLS.dir/dtls-peer.c.o


CMakeFiles/tinyDTLS.dir/dtls-log.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/dtls-log.c.o: ../dtls-log.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/tinyDTLS.dir/dtls-log.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/dtls-log.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-log.c"

CMakeFiles/tinyDTLS.dir/dtls-log.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/dtls-log.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-log.c" > CMakeFiles/tinyDTLS.dir/dtls-log.c.i

CMakeFiles/tinyDTLS.dir/dtls-log.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/dtls-log.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/dtls-log.c" -o CMakeFiles/tinyDTLS.dir/dtls-log.c.s

CMakeFiles/tinyDTLS.dir/dtls-log.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/dtls-log.c.o.requires

CMakeFiles/tinyDTLS.dir/dtls-log.c.o.provides: CMakeFiles/tinyDTLS.dir/dtls-log.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/dtls-log.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/dtls-log.c.o.provides

CMakeFiles/tinyDTLS.dir/dtls-log.c.o.provides.build: CMakeFiles/tinyDTLS.dir/dtls-log.c.o


CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o: ../aes/rijndael.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/aes/rijndael.c"

CMakeFiles/tinyDTLS.dir/aes/rijndael.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/aes/rijndael.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/aes/rijndael.c" > CMakeFiles/tinyDTLS.dir/aes/rijndael.c.i

CMakeFiles/tinyDTLS.dir/aes/rijndael.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/aes/rijndael.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/aes/rijndael.c" -o CMakeFiles/tinyDTLS.dir/aes/rijndael.c.s

CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.requires

CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.provides: CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.provides

CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.provides.build: CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o


CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o: ../ecc/ecc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/ecc/ecc.c"

CMakeFiles/tinyDTLS.dir/ecc/ecc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/ecc/ecc.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/ecc/ecc.c" > CMakeFiles/tinyDTLS.dir/ecc/ecc.c.i

CMakeFiles/tinyDTLS.dir/ecc/ecc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/ecc/ecc.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/ecc/ecc.c" -o CMakeFiles/tinyDTLS.dir/ecc/ecc.c.s

CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.requires

CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.provides: CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.provides

CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.provides.build: CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o


CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o: ../sha2/sha2.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_10) "Building C object CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/sha2/sha2.c"

CMakeFiles/tinyDTLS.dir/sha2/sha2.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/sha2/sha2.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/sha2/sha2.c" > CMakeFiles/tinyDTLS.dir/sha2/sha2.c.i

CMakeFiles/tinyDTLS.dir/sha2/sha2.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/sha2/sha2.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/sha2/sha2.c" -o CMakeFiles/tinyDTLS.dir/sha2/sha2.c.s

CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.requires

CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.provides: CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.provides

CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.provides.build: CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o


CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o: CMakeFiles/tinyDTLS.dir/flags.make
CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o: ../posix/dtls-support.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_11) "Building C object CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o   -c "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/posix/dtls-support.c"

CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/posix/dtls-support.c" > CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.i

CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/posix/dtls-support.c" -o CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.s

CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.requires:

.PHONY : CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.requires

CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.provides: CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.requires
	$(MAKE) -f CMakeFiles/tinyDTLS.dir/build.make CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.provides.build
.PHONY : CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.provides

CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.provides.build: CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o


# Object files for target tinyDTLS
tinyDTLS_OBJECTS = \
"CMakeFiles/tinyDTLS.dir/dtls.c.o" \
"CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o" \
"CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o" \
"CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o" \
"CMakeFiles/tinyDTLS.dir/netq.c.o" \
"CMakeFiles/tinyDTLS.dir/dtls-peer.c.o" \
"CMakeFiles/tinyDTLS.dir/dtls-log.c.o" \
"CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o" \
"CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o" \
"CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o" \
"CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o"

# External object files for target tinyDTLS
tinyDTLS_EXTERNAL_OBJECTS =

libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/dtls.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/netq.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/dtls-peer.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/dtls-log.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/build.make
libtinyDTLS.so: CMakeFiles/tinyDTLS.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_12) "Linking C shared library libtinyDTLS.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tinyDTLS.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/tinyDTLS.dir/build: libtinyDTLS.so

.PHONY : CMakeFiles/tinyDTLS.dir/build

CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/dtls.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/dtls-crypto.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/dtls-ccm.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/dtls-hmac.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/netq.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/dtls-peer.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/dtls-log.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/aes/rijndael.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/ecc/ecc.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/sha2/sha2.c.o.requires
CMakeFiles/tinyDTLS.dir/requires: CMakeFiles/tinyDTLS.dir/posix/dtls-support.c.o.requires

.PHONY : CMakeFiles/tinyDTLS.dir/requires

CMakeFiles/tinyDTLS.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/tinyDTLS.dir/cmake_clean.cmake
.PHONY : CMakeFiles/tinyDTLS.dir/clean

CMakeFiles/tinyDTLS.dir/depend:
	cd "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4" "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4" "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build" "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build" "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver4/build/CMakeFiles/tinyDTLS.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/tinyDTLS.dir/depend
