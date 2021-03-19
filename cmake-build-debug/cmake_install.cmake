# Install script for directory: /home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tinydtls_IPV4__ver6" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tinydtls_IPV4__ver6")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tinydtls_IPV4__ver6"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/cmake-build-debug/tinydtls_IPV4__ver6")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tinydtls_IPV4__ver6" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tinydtls_IPV4__ver6")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tinydtls_IPV4__ver6")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/src" TYPE FILE FILES
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/aes/rijndael.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/aes/rijndael.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/contiki-support/dtls-support-conf.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/contiki-support/dtls-support.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/ecc/tests/test_helper.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/ecc/tests/test_helper.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/ecc/tests/testecc.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/ecc/tests/testfield.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/ecc/ecc.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/ecc/ecc.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/posix/lib/memb.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/posix/dtls-support-conf.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/posix/dtls-support.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/sha2/tests/sha2prog.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/sha2/tests/sha2speed.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/sha2/sha2.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/sha2/sha2.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/cbc_aes128-test.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/cbc_aes128-testdata.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/ccm-test.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/ccm-testdata.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/dsrv-test.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/dtls-client.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/dtls-server.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/netq-test.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/pcap.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/prf-test.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tests/secure-server.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-alert.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-ccm.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-ccm.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-crypto.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-crypto.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-hmac.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-hmac.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-log-default.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-log.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-log.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-numeric.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-peer.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-peer.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-state.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls-support.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/dtls_config.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/netq.c"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/netq.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tesla.h"
    "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/tinydtls.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/user/Dropbox/Modified flights DTLS/tinydtls(IPV4)-ver6/cmake-build-debug/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
