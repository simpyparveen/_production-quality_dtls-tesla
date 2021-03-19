//
// Created by Simpy Parveen on 04/07/19.
/*



#ifndef TINYDTLS_MASTER_IPV4_COPY2_TESLA_H
#define TINYDTLS_MASTER_IPV4_COPY2_TESLA_H

#endif //TINYDTLS_MASTER_IPV4_COPY2_TESLA_H
*/


#include <string.h>

#include "dtls_config.h"

#include "dtls-support-conf.h"

#define TESLA_KEYCHAIN_LEN 1500 //1000

#define T_INTERVAL 1

#define INTERVAL_INDEX 0

#define DIS_DELAY 1

/** Structure of the SERVER TESLA REQUEST message. */
typedef struct{
    uint8_t nonce[32];	//nonce[32]/**< threshold :9153(in MacOS) 59937(in Ubuntu) Client random bytes */
} tesla_request;

/** Structure of the TESLA Synchronization Response. 89-BYTES*/
typedef struct {
    uint8_t nonce[32];            /** 32 BYTES of nonce in request packet */
    uint8_t T_sender[16];           /** 16 BYTES Sender's current time*/
    uint8_t rate[4];              /** 4 BYTES Interval rate */
    uint8_t interval_id[4];       /** 4 ByTES : Interval index ()*/
    uint8_t T_start[16];           /** 16  BYTES : Start Time corresponding to beginning of session Unix GMT*/
    uint8_t T_int[4];             /** 4 BYTES : interval duration (in seconds) */
    uint8_t dis_delay[1];            /** 1 BYTE: Key Disclosure Delay (in number of intervals, eg we want to send 1 key in one interval, where 1 interval is 1RTT, so my rate is 1packet per RTT) */
    uint8_t key_chain_len[4];     /** 4 BYTES : Length of key chain */
    uint8_t Key_comm[32];         /** 32 BYTES: Commitment Key */
} tesla_sync;


/** Structure of the TESLA Extension. 89-BYTES
typedef struct{
    //uint8_t record_header_ext[2];
    uint8_t index[4];
    uint8_t dis_key[32];
    uint8_t tesla_mac[32];
} tesla_ext;
*/
