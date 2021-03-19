cmake_minimum_required(VERSION 3.14)
project(tinydtls_IPV4__ver6 C)

set(CMAKE_C_STANDARD 11)

include_directories(.)
include_directories(aes)
include_directories(contiki-support)
include_directories(ecc)
include_directories(ecc/tests)
include_directories(posix)
include_directories(posix/lib)
include_directories(sha2)

add_executable(tinydtls_IPV4__ver6 #PROJECT_NAME contains
        aes/rijndael.c
        aes/rijndael.h
        contiki-support/dtls-support-conf.h
        contiki-support/dtls-support.c
        ecc/tests/test_helper.c
        ecc/tests/test_helper.h
        ecc/tests/testecc.c
        ecc/tests/testfield.c
        ecc/ecc.c
        ecc/ecc.h
        posix/lib/memb.h
        posix/dtls-support-conf.h
        posix/dtls-support.c
        sha2/tests/sha2prog.c
        sha2/tests/sha2speed.c
        sha2/sha2.c
        sha2/sha2.h
        tests/cbc_aes128-test.c
        tests/cbc_aes128-testdata.c
        tests/ccm-test.c
        tests/ccm-testdata.c
        tests/dsrv-test.c
        tests/dtls-client.c
        tests/dtls-server.c
        tests/netq-test.c
        tests/pcap.c
        tests/prf-test.c
        tests/secure-server.c
        dtls-alert.h
        dtls-ccm.c
        dtls-ccm.h
        dtls-crypto.c
        dtls-crypto.h
        dtls-hmac.c
        dtls-hmac.h
        dtls-log-default.h
        dtls-log.c
        dtls-log.h
        dtls-numeric.h
        dtls-peer.c
        dtls-peer.h
        dtls-state.h
        dtls-support.h
        dtls.c
        dtls.h
        dtls_config.h
        netq.c
        netq.h
        tesla.h
        tinydtls.h)


install(TARGETS tinydtls_IPV4__ver6 DESTINATION bin) #${CMAKE_INSTALL_PREFIX}/bin
install(FILES aes/rijndael.c
        aes/rijndael.h
        contiki-support/dtls-support-conf.h
        contiki-support/dtls-support.c
        ecc/tests/test_helper.c
        ecc/tests/test_helper.h
        ecc/tests/testecc.c
        ecc/tests/testfield.c
        ecc/ecc.c
        ecc/ecc.h
        posix/lib/memb.h
        posix/dtls-support-conf.h
        posix/dtls-support.c
        sha2/tests/sha2prog.c
        sha2/tests/sha2speed.c
        sha2/sha2.c
        sha2/sha2.h
        tests/cbc_aes128-test.c
        tests/cbc_aes128-testdata.c
        tests/ccm-test.c
        tests/ccm-testdata.c
        tests/dsrv-test.c
        tests/dtls-client.c
        tests/dtls-server.c
        tests/netq-test.c
        tests/pcap.c
        tests/prf-test.c
        tests/secure-server.c
        dtls-alert.h
        dtls-ccm.c
        dtls-ccm.h
        dtls-crypto.c
        dtls-crypto.h
        dtls-hmac.c
        dtls-hmac.h
        dtls-log-default.h
        dtls-log.c
        dtls-log.h
        dtls-numeric.h
        dtls-peer.c
        dtls-peer.h
        dtls-state.h
        dtls-support.h
        dtls.c
        dtls.h
        dtls_config.h
        netq.c
        netq.h
        tesla.h
        tinydtls.h
        DESTINATION src) #${CMAKE_INSTALL_PREFIX}/src

