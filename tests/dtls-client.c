//Edited in Clion
#include "tinydtls.h"

/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include "dtls-numeric.h" //added
#include <stdlib.h> //added
#include "dtls.h"
#include <time.h>
/* Log configuration */
#define LOG_MODULE "dtls-client"
#define LOG_LEVEL  LOG_LEVEL_DTLS

#include "dtls-log.h"

#define DEFAULT_PORT 20220
#define DTLS_PSK 1
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#define PSK_OPTIONS          "i:k:"



#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

//added by simpy
dtls_tick_t start_f,stop_f;
double rtt1;

FILE *fp;

static char buf[DTLS_MAX_BUF]; //DTLS_MAX_BUF = 30000
static size_t len = 0;

//Added by simpy
#define READFILE_BYTES 8
clock_t t1,t2;
int bytes_read;

typedef struct {
    size_t length;               /* length of string */
    unsigned char *s;            /* string data */
} dtls_str;

static dtls_str output_file = {0, NULL}; /* output file name */

static dtls_context_t *dtls_context = NULL;
static dtls_context_t *orig_dtls_context = NULL;

static const unsigned char ecdsa_pub_key_x[] = {
        0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
        0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
        0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
        0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52};

static const unsigned char ecdsa_pub_key_y[] = {
        0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
        0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
        0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
        0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29};

#ifdef DTLS_PSK

ssize_t
read_from_file(char *arg, unsigned char *buf, size_t max_buf_len) {
    FILE *f;
    ssize_t result = 0;

    f = fopen(arg, "r");
    if (f == NULL)
        return -1;

    while (!feof(f)) { //!feof() denotes end of file indicator
        size_t bytes_read;
        bytes_read = fread(buf, 1, max_buf_len, f);
        if (ferror(f)) {
            result = -1;
            break;
        }

        buf += bytes_read;
        result += bytes_read;
        max_buf_len -= bytes_read;
    }

    fclose(f);
    return result;
}

/* The PSK information for DTLS */
#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
static unsigned char psk_id[PSK_ID_MAXLEN];
static size_t psk_id_length = 0;
static unsigned char psk_key[PSK_MAXLEN];
static size_t psk_key_length = 0;

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */

static int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
             const session_t *session UNUSED_PARAM,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length) {

printf("\n Inside get_psk_info \n");

    switch (type) {
        case DTLS_PSK_IDENTITY:
            printf("\n Check 1 (get_psk_info): psk_id %s \n",psk_id);
            if (id_len) {
                dtls_debug("got psk_identity_hint: '%.*s'\n", (int) id_len, id);
            }

            if (result_length < psk_id_length) {
                dtls_warn("cannot set psk_identity -- buffer too small\n");
                return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }

            memcpy(result, psk_id, psk_id_length);
            printf("\n Check 2(get_psk_info) : psk_id %s \n",psk_id);

            return psk_id_length;
        case DTLS_PSK_KEY:
            printf("\n check 1(get_psk_info) : psk_key %s \n",psk_key);
            if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
                dtls_warn("PSK for unknown id requested, exiting\n");
                return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
            } else if (result_length < psk_key_length) {
                dtls_warn("cannot set psk -- buffer too small\n");
                return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }

            memcpy(result, psk_key, psk_key_length);
            printf("\n check 2(get_psk_info) : psk_key %s \n",psk_key);

            return psk_key_length;
        default:
            dtls_warn("unsupported request type: %d\n", type);
    }

    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}

#endif /* DTLS_PSK */

//
//#ifdef DTLS_ECC
//static int
//get_ecdsa_key(struct dtls_context_t *ctx,
//	      const session_t *session,
//	      const dtls_ecdsa_key_t **result) {
//  static const dtls_ecdsa_key_t ecdsa_key = {
//    .curve = DTLS_ECDH_CURVE_SECP256R1,
//    .priv_key = ecdsa_priv_key,
//    .pub_key_x = ecdsa_pub_key_x,
//    .pub_key_y = ecdsa_pub_key_y
//  };
//
//  *result = &ecdsa_key;
//  printf("using ecc");
//  return 0;
//}
//
//
//
//static int
//verify_ecdsa_key(struct dtls_context_t *ctx,
//		 const session_t *session,
//		 const unsigned char *other_pub_x,
//		 const unsigned char *other_pub_y,
//		 size_t key_size) {
//  return 0;
//}
//#endif  DTLS_ECC

static void try_send(struct dtls_context_t *ctx, session_t *dst) {
    int res;



    printf("Int index try_send(): ctx->peers->int_index=%u \n",ctx->peers->int_index);


   /* if (ctx->peers->state == DTLS_STATE_CONNECTED && ctx->peers->role == DTLS_CLIENT) {
        //Added yesterday
        t_index = ctx->peers->int_index;
        printf("\n Checking access of Sha Comm key for the sending K[k][32]  Role:%d and t_index = %u and ctx->peers->int_index=%u\n", ctx->peers->role,t_index,ctx->peers->int_index);

        for(int i=0;i<K_len;i++)    printf("%02x\t",ctx->peers->K[t_index][i]);
        p = p + len;
        memcpy(p, ctx->peers->K[t_index], 32);
        p+=32;
        len+=32;
        /*printf("\nContent of buf AFTER adding 32 bytes key has new len as ( len:%zu) :", p - buf);
        for (int j = 0; j < p - buf; ++j) {
            printf("%02x\t", buf[j]);
        }
        ctx->peers->int_index++;
        len+= sizeof(uint32_t);
        len = p - buf;
        */
        res = dtls_write(ctx, dst, (uint8_t *) buf, len);

        printf("Initial Len=%d and res=%d ",len,res);
    /*if (res >= 0) {
        memmove(buf, buf + res, len - res);//n=memmove(dest,src,no_of_bytes_to be copied)
        len -= res;
    }*/
    len=0;
    printf("Final Len=%d and res=%d ",len,res);
}

static void
handle_stdin() {
    if (fgets(buf + len, sizeof(buf) - len, stdin))
        len += strlen(buf + len);
}


static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%c", data[i]);

    return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx,
             session_t *session, uint8_t *data, size_t len) {

    int fd = *(int *) dtls_get_app_data(ctx);
    return sendto(fd, data, len, MSG_DONTWAIT,
                  &session->addr.sa, session->size);
}

static int
dtls_handle_read(struct dtls_context_t *ctx) {
    int fd;
    session_t session;
#define MAX_READ_BUF 30000
    //tesla:21331
    static uint8_t buf[MAX_READ_BUF];
    int len;

    fd = *(int *) dtls_get_app_data(ctx);

    if (!fd)
        return -1;

    memset(&session, 0, sizeof(session_t));
    session.size = sizeof(session.addr);
    len = recvfrom(fd, buf, MAX_READ_BUF, 0,
                   &session.addr.sa, &session.size);

    if (len < 0) {
        perror("recvfrom");
        return -1;
    } else {
        dtls_debug_session("peer", &session);
        dtls_debug_dump("bytes from peer", buf, len);
    }

    return dtls_handle_message(ctx, &session, buf, len);
}

static void dtls_handle_signal(int sig) {
    dtls_free_context(dtls_context);
    dtls_free_context(orig_dtls_context);
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
}

/* stolen from libcoap: */
static int
resolve_address(const char *server, struct sockaddr *dst) {

    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    static char addrstr[256];
    int error;

    memset(addrstr, 0, sizeof(addrstr));
    if (server && strlen(server) > 0)
        memcpy(addrstr, server, strlen(server));
    else
        memcpy(addrstr, "localhost", 9);

    memset((char *) &hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(addrstr, "", &hints, &res);

    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return error;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

        switch (ainfo->ai_family) {
            case AF_INET6:
            case AF_INET:

                memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
                return ainfo->ai_addrlen;
            default:;
        }
    }

    freeaddrinfo(res);
    return -1;
}

/*---------------------------------------------------------------------------*/
static void
usage(const char *program, const char *version) {
    const char *p;

    p = strrchr(program, '/');
    if (p)
        program = ++p;

    fprintf(stderr, "%s v%s -- DTLS client implementation\n"
                    "(c) 2011-2014 Olaf Bergmann <bergmann@tzi.org>\n\n"
                    #ifdef DTLS_PSK
                    "usage: %s [-i file] [-k file] [-o file] [-p port] [-v num] addr [port]\n"
                    #else /*  DTLS_PSK */
                    "usage: %s [-o file] [-p port] [-v num] addr [port]\n"
                    #endif /* DTLS_PSK */
                    #ifdef DTLS_PSK
                    "\t-i file\t\tread PSK identity from file\n"
                    "\t-k file\t\tread pre-shared key from file\n"
                    #endif /* DTLS_PSK */
                    "\t-o file\t\toutput received data to this file (use '-' for STDOUT)\n"
                    "\t-p port\t\tlisten on specified port (default is %d)\n",
            program, version, program, DEFAULT_PORT);
}

static dtls_handler_t cb = {
        .write = send_to_peer,
        .read  = read_from_peer,
        .event = NULL,

#ifdef DTLS_PSK
        .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
//#ifdef DTLS_ECC
        // .get_ecdsa_key = get_ecdsa_key,
        // .verify_ecdsa_key = verify_ecdsa_key
//#endif /* DTLS_ECC */
};

#define DTLS_CLIENT_CMD_CLOSE "client:close"
#define DTLS_CLIENT_CMD_RENEGOTIATE "client:renegotiate"

/* As per RFC 6347 section 4.2.8, DTLS Server should support requests
 * from clients who have silently abandoned the existing association
 * and initiated a new handshake request by sending a ClientHello.
 * Below command tests this feature.
 */
#define DTLS_CLIENT_CMD_REHANDSHAKE "client:rehandshake"


/************* DTLS main function ****************/
int main(int argc, char **argv) {
    fd_set rfds, wfds;
    struct timeval timeout;
    unsigned short port = DEFAULT_PORT;
    char port_str[NI_MAXSERV] = "0";
    int fd, result;
    int on = 1;
    int opt, res;
    int filefd;
    session_t dst;


    dtls_init();
    snprintf(port_str, sizeof(port_str), "%d", port); //counting characters and storing in port_str
    printf("\nDefault port %d \n", port);
#ifdef DTLS_PSK
    psk_id_length = strlen(PSK_DEFAULT_IDENTITY);
    psk_key_length = strlen(PSK_DEFAULT_KEY);
    memcpy(psk_id, PSK_DEFAULT_IDENTITY, psk_id_length);
    memcpy(psk_key, PSK_DEFAULT_KEY, psk_key_length);
#endif /* DTLS_PSK */

    while ((opt = getopt(argc, argv, "p:o:"PSK_OPTIONS)) != -1) {
        switch (opt) {
            printf("\n Inside opt PSK_OPTIONS \n");
#ifdef DTLS_PSK
            case 'i' : {
                printf("\n Check 1(Inside opt PSK_OPTIONS) : Inside case 'i'  : %s", psk_id);
                ssize_t result = read_from_file(optarg, psk_id, PSK_ID_MAXLEN);
                if (result < 0) {
                    dtls_warn("cannot read PSK identity\n");
                } else {
                    printf("psk_id_length \n");
                    psk_id_length = result;
                }
                printf("\n Check 2(Inside opt PSK_OPTIONS): Inside case 'i'  : %s", psk_id);
            }break;
            case 'k' : {
                printf("\n Check 1(Inside opt PSK_OPTIONS): Inside case 'k'  : %s", psk_key);
                ssize_t result = read_from_file(optarg, psk_key, PSK_MAXLEN);
                if (result < 0) {
                    dtls_warn("cannot read PSK\n");
                } else {
                    printf("psk_key_length \n");
                    psk_key_length = result;
                }
                printf("\n Check 2(Inside opt PSK_OPTIONS): Inside case 'k'  : %s", psk_key);
                break;
            }
#endif /* DTLS_PSK */
            case 'p' :
                strncpy(port_str, optarg, NI_MAXSERV - 1);
                port_str[NI_MAXSERV - 1] = '\0';
                break;
            case 'o' :
                output_file.length = strlen(optarg);
                output_file.s = (unsigned char *) malloc(output_file.length + 1);

                if (!output_file.s) {
                    dtls_crit("cannot set output file: insufficient memory\n");
                    exit(-1);
                } else {
                    /* copy filename including trailing zero */
                    memcpy(output_file.s, optarg, output_file.length + 1);
                }
                break;
            default:
                usage(argv[0], dtls_package_version());
                exit(1);
        }
    }

    if (argc <= optind) {
        usage(argv[0], dtls_package_version());
        exit(1);
    }

    memset(&dst, 0, sizeof(session_t));
    /* resolve destination address where server should be sent */
    res = resolve_address(argv[optind++], &dst.addr.sa);
    printf("Server address %s\n", argv[optind - 1]);
    if (res < 0) {
        dtls_emerg("failed to resolve address\n");
        exit(-1);
    }
    dst.size = res;

    /* use port number from command line when specified or the listen port, otherwise */
    dst.addr.sin.sin_port = htons(DEFAULT_PORT);
    // dst.addr.sin.sin_port = htons(atoi(optind < argc ? argv[optind++] : port_str));
    printf(" Client listen port is set to defualt ?? : %d", dst.addr.sin.sin_port);

    /* Socket Creation : init socket and set it to non-blocking */
    fd = socket(dst.addr.sa.sa_family, SOCK_DGRAM, 0);

    if (fd < 0) {
        dtls_alert("socket: %s\n", strerror(errno));
        return 0;
    }
    /* SO_REUSEADDR is option name and its value is given by &on as 0 or 1, here 1. This allows use of local addreses*/
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        dtls_alert("setsockopt SO_REUSEADDR: %s\n", strerror(errno));
    }
#if 0
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      dtls_alert("fcntl: %s\n", strerror(errno));
      goto error;
    }
#endif
    on = 1;
#ifdef IPV4_RECVPKTINFO

    if (setsockopt(fd, IPPROTO_IP, IP_RECVPKTINFO, &on, sizeof(on) ) < 0) {
      dtls_alert("setsockopt IP_PKTINFO: %s\n", strerror(errno));
    }
#elif defined IP_PKTINFO
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
        dtls_alert("setsockopt IP_PKTINFO: %s\n", strerror(errno));
    }
#else
    dtls_alert("setsockopt IP_PKTINFO not supported\n");
#endif /* IP_RECVPKTINFO */

    if (signal(SIGINT, dtls_handle_signal) == SIG_ERR) {
        dtls_alert("An error occurred while setting a signal handler.\n");
        return EXIT_FAILURE;
    }

    dtls_context = dtls_new_context(&fd);
    if (!dtls_context) {
        dtls_emerg("cannot create context\n");
        exit(-1);
    }

    dtls_set_handler(dtls_context, &cb);
//  dtls_connect(dtls_context, &dst);
    int ret = dtls_connect(dtls_context, &dst);
	dtls_ticks(&start_f);
	t1 = clock();

/** Reading Handshake messages*/
    while (1)
    {
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(fd, &rfds);           //fd =socket ()

        //FD_SET(fileno(stdin),&rfds);
        //FD_SET(fd, &wfds);

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        result = select(fd + 1, &rfds, &wfds, 0, &timeout);

        if (result < 0) {        /* error */
            if (errno != EINTR)
                perror("select");
        } else if (result == 0) {    /* timeout */
        } else {                 /* ok */
            if (FD_ISSET(fd, &rfds)) {
                dtls_handle_read(dtls_context);
				printf("Read from fd:%d \tState:%d, Role:%d\n",fd, dtls_context->peers->state, dtls_context->peers->role);
            }
        }

//Get out of while after handshake is completed
        if (dtls_context->peers->state == 12 && (dtls_context->peers->role == 0 || dtls_context->peers->role == 1)) {
            printf("\nConnection complete\n");
            break;
        }
    }



/**Start Reading from the file*/
    fp = fopen("f1.txt", "r");
    filefd = fileno(fp);

    printf("Open the file\n");

    while (1) {
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        FD_SET(fd, &rfds);
        FD_SET(fd, &wfds);
        FD_SET(filefd, &rfds);

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        result = select(max(fd, filefd) + 1, &rfds, &wfds, 0, &timeout);

        if (result < 0) {
            perror("Transmitting data from file");
        } else if (result == 0) {
            /* Time out */
        } else { // Find something to read or write
            if (FD_ISSET(filefd, &rfds)) {
                // Read something from the file
                //bytes_read = read(filefd, buf + len, sizeof(buf) - len);
                bytes_read = read(filefd, buf, READFILE_BYTES);
                if (bytes_read == 0) {
             //printf("File is over and Time for sending file  %lf seconds",(double)t2/CLOCKS_PER_SEC);
                    dtls_ticks(&stop_f);
			t2 = clock() - t1;
                    printf("Time sending file %d ticks and %lf seconds",(stop_f-start_f),(double)t2/CLOCKS_PER_SEC);
                    break;
                }
                len += bytes_read;
                printf("Len: %d\n", len);
            } else if (FD_ISSET(fd, &rfds)) {
                dtls_handle_read(dtls_context);
            }

            if (len > 0) {
                if (len >= strlen(DTLS_CLIENT_CMD_CLOSE) &&
                    !memcmp(buf, DTLS_CLIENT_CMD_CLOSE, strlen(DTLS_CLIENT_CMD_CLOSE))) {
                    printf("client: closing connection\n");
                    dtls_close(dtls_context, &dst);
                    len = 0;
                } else if (len >= strlen(DTLS_CLIENT_CMD_RENEGOTIATE) &&
                           !memcmp(buf, DTLS_CLIENT_CMD_RENEGOTIATE, strlen(DTLS_CLIENT_CMD_RENEGOTIATE))) {
                    printf("client: renegotiate connection\n");
                    dtls_renegotiate(dtls_context, &dst);
                    len = 0;
                } else if (len >= strlen(DTLS_CLIENT_CMD_REHANDSHAKE) &&
                           !memcmp(buf, DTLS_CLIENT_CMD_REHANDSHAKE, strlen(DTLS_CLIENT_CMD_REHANDSHAKE))) {
                    printf("client: rehandshake connection\n");
                    if (orig_dtls_context == NULL) {
                        /* Cache the current context. We cannot free the current context as it will notify
                         * the Server to close the connection (which we do not want).
                         */

                        orig_dtls_context = dtls_context;
                        // Now, Create a new context and attempt to initiate a handshake.
                        dtls_context = dtls_new_context(&fd);
                        if (!dtls_context) {
                            dtls_emerg("cannot create context\n");
                            exit(-1);
                        }
                        dtls_set_handler(dtls_context, &cb);
                        dtls_connect(dtls_context, &dst);
                    }
                    len = 0;
                } else {
                    // delay of one second
                   //sleep(0.002); //added for maintain rate = 1 rtt per packet
                    try_send(dtls_context, &dst);
                }
            }
            //printf("\n Sending Data :\t");
            int i;
            for (i = 0; i < sizeof(buf); i++)
                buf[i] = '\0';
            printf("%s\n",buf);
        }
    }

    fclose(fp);
    dtls_free_context(dtls_context);
    dtls_free_context(orig_dtls_context);
    exit(0);
}