//Edited in Clion
/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>
#include "tinydtls.h"
#include "dtls.h"

/* Log configuration */
#define LOG_MODULE "dtls-server"
#define LOG_LEVEL  LOG_LEVEL_DTLS

#include "dtls-log.h"

#define DEFAULT_PORT 20220

static char buf[30000];
static size_t len = 0;
static const unsigned char ecdsa_priv_key[] = {
        0xD9, 0xE2, 0x70, 0x7A, 0x72, 0xDA, 0x6A, 0x05,
        0x04, 0x99, 0x5C, 0x86, 0xED, 0xDB, 0xE3, 0xEF,
        0xC7, 0xF1, 0xCD, 0x74, 0x83, 0x8F, 0x75, 0x70,
        0xC8, 0x07, 0x2D, 0x0A, 0x76, 0x26, 0x1B, 0xD4};

static const unsigned char ecdsa_pub_key_x[] = {
        0xD0, 0x55, 0xEE, 0x14, 0x08, 0x4D, 0x6E, 0x06,
        0x15, 0x59, 0x9D, 0xB5, 0x83, 0x91, 0x3E, 0x4A,
        0x3E, 0x45, 0x26, 0xA2, 0x70, 0x4D, 0x61, 0xF2,
        0x7A, 0x4C, 0xCF, 0xBA, 0x97, 0x58, 0xEF, 0x9A};

static const unsigned char ecdsa_pub_key_y[] = {
        0xB4, 0x18, 0xB6, 0x4A, 0xFE, 0x80, 0x30, 0xDA,
        0x1D, 0xDC, 0xF4, 0xF4, 0x2E, 0x2F, 0x26, 0x31,
        0xD0, 0x43, 0xB1, 0xFB, 0x03, 0xE2, 0x2F, 0x4D,
        0x17, 0xDE, 0x43, 0xF9, 0xF9, 0xAD, 0xEE, 0x70};

#if 0
/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  dsrv_stop(dsrv_get_context());
}
#endif

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
         dtls_credentials_type_t type,
         const unsigned char *id, size_t id_len,
         unsigned char *result, size_t result_length) {

    printf("\nget_psk_info() error check 1 \n");

  struct keymap_t {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[4] = {
    { (unsigned char *)"Client_identity", 15,
      (unsigned char *)"secretPSK", 9 },
    { (unsigned char *)"default identity", 1,
      (unsigned char *)"\x11\x22\x33", 3 },
    { (unsigned char *)"\0", 2,
      (unsigned char *)"", 1 },
      { (unsigned char *)"Simpy_identity", 14,
      (unsigned char *)"Simpy_key", 9 }
  };

  if (type != DTLS_PSK_KEY) {
    printf("\nget_psk_info() error check 2 \n");
      return 0;
  }

  if (id) {
    printf("\nget_psk_info() error check 3 : %s \n",id);
      int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
      printf("\nget_psk_info() error check 3.1 : %s, client's id length :%zu, my id length :%zu \n",id, id_len, psk[i].id_length);
        if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
    printf("\n get_psk_info() error check 4 \n");
          if (result_length < psk[i].key_length) {
      printf("\nget_psk_info() error check 5 \n");
        dtls_warn("buffer too small for PSK");
        printf("\nget_psk_info() error check 6 \n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }
printf("\nget_psk_info() error check 7 :%s \n",psk[i].key);

    memcpy(result, psk[i].key, psk[i].key_length);
    return psk[i].key_length;
      }
    }
  }

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}

#endif /* DTLS_PSK */

/*#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP25R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}
#endif /* DTLS_ECC */

#define DTLS_SERVER_CMD_CLOSE "server:close"
#define DTLS_SERVER_CMD_RENEGOTIATE "server:renegotiate"

//added from client
static void try_send(struct dtls_context_t *ctx, session_t *dst) {
    // printf("\nDebug 2 in try_send message = %s \n",buf);
    int res;

    res = dtls_write(ctx, dst, (uint8_t *) buf, len);

    if (res >= 0) {
        memmove(buf, buf + res, len - res);
        len -= res;
    }
}


static int
read_from_peer(struct dtls_context_t *ctx,
               session_t *session, uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%c", data[i]);
    if (len >= strlen(DTLS_SERVER_CMD_CLOSE) &&
        !memcmp(data, DTLS_SERVER_CMD_CLOSE, strlen(DTLS_SERVER_CMD_CLOSE))) {
        printf("server: closing connection\n");
        dtls_close(ctx, session);
        return len;
    } else if (len >= strlen(DTLS_SERVER_CMD_RENEGOTIATE) &&
               !memcmp(data, DTLS_SERVER_CMD_RENEGOTIATE, strlen(DTLS_SERVER_CMD_RENEGOTIATE))) {
        printf("server: renegotiate connection\n");
        dtls_renegotiate(ctx, session);
        return len;
    }

    return dtls_write(ctx, session, data, len); //return 0 for session reuse
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
    int *fd;
    session_t session;
    static uint8_t buf[DTLS_MAX_BUF];
    int len;
    char str[INET_ADDRSTRLEN];
    fd = dtls_get_app_data(ctx);

    assert(fd);

    memset(&session, 0, sizeof(session_t));
    session.size = sizeof(session.addr);
    len = recvfrom(*fd, buf, sizeof(buf), MSG_TRUNC, &session.addr.sa,
                   &session.size); //MSG_TRUNC indicates that the buffer space provided for receiving was insufficient, so that some of the packet data were lost.
    // printf("\nReceived from %s \n",inet_ntoa((session.addr.sin).sin_addr));

    if (len < 0) {
        perror("recvfrom");
        return -1;
    } else {
        dtls_debug("got %d bytes from  client port %d\n", len, ntohs(session.addr.sin.sin_port));
        // printf("got %d bytes from  port %d and IP : %s \n", len,ntohs(session.addr.sin.sin_port),inet_ntoa((session.addr.sin).sin_addr));

        //printf("Client address in sa: %s \n",inet_ntoa((session.addr.sin).sin_addr));  //sin is type sockaddr_in, so we want sin_addr from struct sockaddr_in

        if (sizeof(buf) < len) {
            dtls_warn("packet was truncated (%d bytes lost)\n", (int) (len - sizeof(buf)));
        }
    }

    return dtls_handle_message(ctx, &session, buf, len);
}


static int resolve_address(const char *server, struct sockaddr *dst) {

    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    static char addrstr[256];
    int error;
    printf("\n resolve address : %s \n", server);
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
            case AF_INET:

                memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
                return ainfo->ai_addrlen;
            default:;
        }
    }

    freeaddrinfo(res);
    return -1;
}

static void usage(const char *program, const char *version) {
    const char *p;

    p = strrchr(program, '/');
    if (p)
        program = ++p;

    fprintf(stderr, "%s v%s -- DTLS server implementation\n"
                    "(c) 2011-2014 Olaf Bergmann <bergmann@tzi.org>\n\n"
                    "usage: %s [-A address] [-p port] [-v num]\n"
                    "\t-A address\t\tserver on specified address (default is ::)\n"
                    "\t-p port\t\tserver on specified port (default is %d)\n",
            program, version, program, DEFAULT_PORT);
}

static dtls_handler_t cb = {
        .write = send_to_peer,
        .read  = read_from_peer,
        .event = NULL,
#ifdef DTLS_PSK
        .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */


/* 
#ifdef DTLS_ECC
  .get_ecdsa_key = get_ecdsa_key,
  .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
};


static void
handle_stdin() {
    if (fgets(buf + len, sizeof(buf) - len, stdin))
        len += strlen(buf + len);
}

//Main Function
int main(int argc, char **argv) {
    dtls_context_t *the_context = NULL;
    fd_set rfds, wfds;
    struct timeval timeout;
    int fd, opt, result;
    int on = 1;
    struct sockaddr_in server_addr;

    //added
    // session_t dst;//destination for the server is client, so dst is client address

    memset(&server_addr, 0, sizeof(struct sockaddr_in));

    /* fill extra field for 4.4BSD-based systems (see RFC 3493, section 3.4) */
#if defined(SIN_LEN) || defined(HAVE_SOCKADDR_IN_SIN_LEN)
    server_addr.sin_len = sizeof(struct sockaddr_in);
#endif

//servering address or server information
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);


    while ((opt = getopt(argc, argv, "A:p:")) != -1) {
        switch (opt) {
            case 'A' :
                if (resolve_address(optarg, (struct sockaddr *) &server_addr) < 0) {
                    fprintf(stderr, "cannot resolve address\n");
                    exit(-1);
                }
                break;
            case 'p' :
                server_addr.sin_port = htons(atoi(optarg));
                printf("\n server port : %d \t ", server_addr.sin_port);
                break;
            default:
                usage(argv[0], dtls_package_version());
                exit(1);
        }
    }

    /* init socket and set it to non-blocking */
    fd = socket(server_addr.sin_family, SOCK_DGRAM, 0);

    if (fd < 0) {
        dtls_alert("socket: %s\n", strerror(errno));
        return 0;
    }

    /* SO_REUSEADDR is option name and its value is given by &on as 0 or 1, here 1. This allows use of local addresses*/
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
#ifdef IP_RECVPKTINFO
    if (setsockopt(fd, IPPROTO_IP, IP_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IP_RECVPKTINFO */
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
#endif /* IP_RECVPKTINFO */
        dtls_alert("setsockopt IP_PKTINFO: %s\n", strerror(errno));
    }

    //Bind the socket with server address
    if (bind(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        dtls_alert("bind: %s\n", strerror(errno));
        goto error;
    }

    dtls_init();//Initializes memory management and must be called first

    the_context = dtls_new_context(&fd); //holds global information of DTLS engine

    dtls_set_handler(the_context, &cb); //read/write/alert



    while (1) {


        FD_ZERO(&rfds);
        FD_ZERO(&wfds);


        FD_SET(fd, &rfds);
        FD_SET(fileno(stdin), &rfds); //stdin=0
        /* FD_SET(fd, &wfds); */

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        result = select(fd + 1, &rfds, &wfds, 0, &timeout);

        if (result < 0) {        /* error */
            if (errno != EINTR)
                perror("select");
        } else if (result == 0) {    /* timeout */
        } else {            /* ok */
            if (FD_ISSET(fd, &wfds)) {
                //printf("\nServer check:FD_ISSET(fd, &wfds) :Do nothing\n")
                ; /* Do nothing */
            }
            else if (FD_ISSET(fd, &rfds)) {
                //printf("\nServer check:FD_ISSET(fd, &rfds) \n");
                dtls_handle_read(the_context);
            }

            else if (FD_ISSET(fileno(stdin), &rfds)) {
                //printf("\nhandle_stdin\n");
                handle_stdin();
            }
        }
    }
    error:
    dtls_free_context(the_context);
    exit(0);
}
