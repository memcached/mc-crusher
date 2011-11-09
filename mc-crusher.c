/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *  mc-crusher - make the rabbit fear you
 *
 *       https://github.com/dormando/mc-crusher
 *
 *  Copyright 2011 Dormando.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      dormando <dormando@rydia.net>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <event.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <sysexits.h>
#include <stddef.h>
#include <sys/stat.h>

#include "protocol_binary.h"

uint64_t counter;
uint64_t reset_counter_after;
unsigned char *shared_value;
unsigned char *shared_rbuf[1024 * 64];

enum conn_states {
    conn_connecting = 0,
    conn_sending,
    conn_reading,
};

struct mc_key {
    unsigned char *key;
    size_t key_len;
};

struct connection {
    /* host */
    char ip_addr[60];
    int port_num;

    /* Event stuff */
    int fd;
    struct event ev;
    enum conn_states state;
    short ev_flags;

    /* Counters, bits, flags for individual senders/getters .
     * This isn't a union because who gives a shit.
     */
    int mget_count;                /* # of ascii mget keys to send at once */
    unsigned char key_prefix[240];
    int value_size;
    unsigned char value[2048];     /* manually specified seed value */
    int buf_written;
    int buf_towrite;

    /* Binprot headers */
    protocol_binary_request_get bin_get_pkt;
    protocol_binary_request_set bin_set_pkt;

    /* Buffers */
    uint64_t key_count;
    uint64_t key_randomize;
    uint64_t cur_key;
    int      key_prealloc;
    struct mc_key *keys;
    unsigned char wbuf[65536];

    /* iovectors */
    struct iovec *vecs;
    int    iov_count; /* iovecs in use */
    int    iov_towrite; /* bytes to write */

    /* reader/writer function pointers */
    void (*writer)(void *arg);
    void (*reader)(void *arg);
};

static struct event_base *main_base;

static void client_handler(const int fd, const short which, void *arg);

static int update_conn_event(struct connection *c, const int new_flags)
{
    if (c->ev_flags == new_flags) return 1;
    if (event_del(&c->ev) == -1) return 0;

    c->ev_flags = new_flags;
    event_set(&c->ev, c->fd, new_flags, client_handler, (void *)c);
    event_base_set(main_base, &c->ev);

    if (event_add(&c->ev, 0) == -1) return 0;
    return 1;
}

/* TODO: Be more wary of IOV_MAX */
static void drain_iovecs(struct iovec *vecs, const int iov_count, const int written) {
    int i;
    int todrain = written;
    for (i = 0; i < iov_count; i++) {
        if (vecs[i].iov_len > 0) {
            if (todrain >= vecs[i].iov_len) {
                todrain -= vecs[i].iov_len;
                vecs[i].iov_base = NULL;
                vecs[i].iov_len  = 0;
            } else {
                vecs[i].iov_len -= todrain;
                vecs[i].iov_base += todrain;
                break;
            }
        }
    }
}

static void write_iovecs(struct connection *c, enum conn_states next_state) {
    int written = 0;
    written = writev(c->fd, c->vecs, c->iov_count);
    if (written == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            c->state = conn_reading;
            return;
        } else {
            perror("Write error to client");
            exit(1);
            return;
        }
    }

    c->iov_towrite -= written;
    if (c->iov_towrite > 0) {
        update_conn_event(c, EV_READ | EV_WRITE | EV_PERSIST);
        fprintf(stderr, "Draining iovecs to %d (%d)\n", c->iov_towrite, written);
        drain_iovecs(c->vecs, c->iov_count, written);
        c->state = conn_sending;
    } else {
        c->state = next_state;
        if (c->state == conn_reading) {
            update_conn_event(c, EV_READ | EV_PERSIST);
        }
    }
}

static inline int sum_iovecs(const struct iovec *vecs, const int iov_count) {
    int i;
    int sum = 0;
    for (i = 0; i < iov_count; i++) {
        sum += vecs[i].iov_len;
    }
    return sum;
}

static inline void run_counter(struct connection *c) {
    if (++c->cur_key >= c->key_count) {
        fprintf(stdout, "Did %llu writes\n", (unsigned long long)c->key_count);
        c->cur_key = 0;
    }
}

static void write_bin_get_to_client(void *arg) {
    struct connection *c = arg;
    int wbytes = 0;
    uint32_t keylen = 0;

    keylen = sprintf(c->wbuf + sizeof(c->bin_get_pkt), "%s%llu", c->key_prefix,
        (unsigned long long)c->cur_key);
    c->bin_get_pkt.message.header.request.keylen = htons(keylen);
    c->bin_get_pkt.message.header.request.bodylen = htonl(keylen);
    memcpy(c->wbuf, (char *)&c->bin_get_pkt.bytes, sizeof(c->bin_get_pkt));
    wbytes = send(c->fd, c->wbuf, sizeof(c->bin_get_pkt) + keylen, 0);
    c->state = conn_reading;
    run_counter(c);
}

static void write_bin_getq_to_client(void *arg) {
    struct connection *c = arg;
    int wbytes = 0;
    uint32_t keylen = 0;
    int towrite = 0;
    size_t psize = sizeof(c->bin_get_pkt);

    /* existing buffer we need to finish flushing */
    if (c->buf_towrite) {
        wbytes = send(c->fd, c->wbuf + c->buf_written, c->buf_towrite, 0);
        if (wbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                c->state = conn_reading;
                return;
            } else {
                perror("Early write error to client");
                return;
            }
        } else if (wbytes < c->buf_towrite) {
            c->state = conn_reading;
            c->buf_towrite -= wbytes;
            c->buf_written += wbytes;
            return;
        }
        c->buf_towrite = 0;
        c->buf_written = 0;
    }

    for(;;) {
        towrite = 0;
        while (towrite < (4096 - (psize + 250))) {
            keylen = sprintf(c->wbuf + towrite + psize, "%s%llu",
                c->key_prefix, (unsigned long long)c->cur_key);
            c->bin_get_pkt.message.header.request.keylen = htons(keylen);
            c->bin_get_pkt.message.header.request.bodylen = htonl(keylen);
            memcpy(c->wbuf + towrite, (char *)&c->bin_get_pkt.bytes, psize);
            towrite += keylen + psize;
            run_counter(c);
        }
        wbytes = send(c->fd, c->wbuf, towrite, 0);
        if (wbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                c->state = conn_reading;
                c->buf_towrite = towrite;
                return;
            } else {
                perror("Late write error to client");
                return;
            }
        } else if (wbytes < towrite) {
            c->state = conn_reading;
            c->buf_towrite = towrite - wbytes;
            c->buf_written = wbytes;
            return;
        }
    }

    return;
}

static void write_bin_set_to_client(void *arg) {
    struct connection *c = arg;
    int wbytes = 0;
    uint32_t keylen = 0;

    keylen = sprintf(c->wbuf + sizeof(c->bin_set_pkt), "%s%llu", c->key_prefix,
        (unsigned long long)c->cur_key);
    c->bin_set_pkt.message.header.request.keylen = htons(keylen);
    c->bin_set_pkt.message.header.request.bodylen = htonl(keylen +
        c->value_size + 8);
    memcpy(c->wbuf, (char *)&c->bin_set_pkt.bytes, sizeof(c->bin_set_pkt));
    wbytes = send(c->fd, c->wbuf, sizeof(c->bin_set_pkt) + keylen, 0);
    if (c->value[0] == '\0') {
        wbytes = send(c->fd, shared_value, c->value_size, 0);
    } else {
        wbytes = send(c->fd, c->value, c->value_size, 0);
    }

    c->state = conn_reading;
    run_counter(c);

    return;
}

static void write_bin_setq_to_client(void *arg) {
    struct connection *c = arg;
    int wbytes = 0;
    uint32_t keylen = 0;
    int towrite = 0;
    size_t psize = sizeof(c->bin_set_pkt);

    update_conn_event(c, EV_READ | EV_WRITE | EV_PERSIST);
    /* existing buffer we need to finish flushing */
    if (c->buf_towrite) {
        wbytes = send(c->fd, c->wbuf + c->buf_written, c->buf_towrite, 0);
        if (wbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                c->state = conn_sending;
                return;
            } else {
                perror("Early write error to client");
                return;
            }
        } else if (wbytes < c->buf_towrite) {
            c->state = conn_reading;
            c->buf_towrite -= wbytes;
            c->buf_written += wbytes;
            return;
        }
        c->buf_towrite = 0;
        c->buf_written = 0;
    }

    for(;;) {
        towrite = 0;
        while (towrite < (4096 - (psize + 250))) {
            keylen = sprintf(c->wbuf + towrite + psize, "%s%llu",
                c->key_prefix, (unsigned long long)c->cur_key);
            c->bin_set_pkt.message.header.request.keylen = htons(keylen);
            c->bin_set_pkt.message.header.request.bodylen = htonl(keylen + 8 +
                c->value_size);
            memcpy(c->wbuf + towrite, (char *)&c->bin_set_pkt.bytes, psize);
            towrite += keylen + psize;
            if (c->value[0] == '\0') {
                memcpy(c->wbuf + towrite, shared_value, c->value_size);
            } else {
                memcpy(c->wbuf + towrite, c->value, c->value_size);
            }
            towrite += c->value_size;

            run_counter(c);
        }
        wbytes = send(c->fd, c->wbuf, towrite, 0);
        if (wbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                c->state = conn_sending;
                c->buf_towrite = towrite;
                return;
            } else {
                perror("Late write error to client");
                return;
            }
        } else if (wbytes < towrite) {
            c->state = conn_sending;
            c->buf_towrite = towrite - wbytes;
            c->buf_written = wbytes;
            return;
        }
    }

    return;
}

static void write_ascii_mget_to_client(void *arg) {
    struct connection *c = arg;
    int wbytes = 0;
    int written = 0;
    int i;
    strcpy(c->wbuf, "get ");
    written += 4;
    for (i = 0; i < c->mget_count; i++) {
        written += sprintf(c->wbuf + written, "%s%llu ",
            c->key_prefix, (unsigned long long)c->cur_key);
        run_counter(c);
    }
    strcpy(c->wbuf + (written), "\r\n");
    wbytes = send(c->fd, &c->wbuf, written + 2, 0);
    c->state = conn_reading;
}

static void prealloc_write_ascii_mget_to_client(void *arg) {
    struct connection *c = arg;
    int i;
    struct iovec *vecs = c->vecs;
    vecs[0].iov_base = "get ";
    vecs[0].iov_len  = 4;
    for (i = 1; i < c->mget_count + 1; i++) {
        vecs[i].iov_base = c->keys[c->cur_key].key;
        vecs[i].iov_len  = c->keys[c->cur_key].key_len;
        run_counter(c);
    }
    vecs[i].iov_base = "\r\n";
    vecs[i].iov_len  = 2;
    c->iov_towrite = sum_iovecs(vecs, c->iov_count);
    write_iovecs(c, conn_reading);
}

static void write_ascii_get_to_client(void *arg) {
    struct connection *c = arg;
    int wbytes = 0;
    sprintf(c->wbuf, "get %s%llu\r\n", c->key_prefix,
        (unsigned long long)c->cur_key);
    wbytes = send(c->fd, &c->wbuf, strlen(c->wbuf), 0);
    c->state = conn_reading;
    run_counter(c);
}

/* Example of how to rewrite these functions.
   This *greatly* reduces the user cpu time, however the bench spends almost
   all of its time in the syscalls already.
   So I'm not prioritizing this change right now.
 */
static void prealloc_write_ascii_get_to_client(void *arg) {
    struct connection *c = arg;
    struct iovec *vecs = c->vecs;
    vecs[0].iov_base = "get ";
    vecs[0].iov_len = 4;
    vecs[1].iov_base = c->keys[c->cur_key].key;
    vecs[1].iov_len  = c->keys[c->cur_key].key_len;
    vecs[2].iov_base = "\r\n";
    vecs[2].iov_len = 2;

    c->iov_towrite = sum_iovecs(vecs, c->iov_count);
    write_iovecs(c, conn_reading);
    run_counter(c);
}

/* Will break hard if value is too large to write in one go.
   Need to add a "load iovec -> drain iovec" process
 */
static void write_ascii_set_to_client(void *arg) {
    struct connection *c = arg;
    struct iovec *vecs = c->vecs;
    vecs[0].iov_base = c->wbuf;
    vecs[0].iov_len  = sprintf(c->wbuf, "set %s%llu 0 0 %d\r\n", c->key_prefix,
        (unsigned long long)c->cur_key, c->value_size);
    if (c->value[0] == '\0') {
        vecs[1].iov_base = shared_value;
    } else {
        vecs[1].iov_base = c->value;
    }
    vecs[1].iov_len  = c->value_size;
    vecs[2].iov_base = "\r\n";
    vecs[2].iov_len  = 2;
    c->iov_towrite = sum_iovecs(vecs, c->iov_count);
    write_iovecs(c, conn_reading);

    run_counter(c);
}

static void read_from_client(void *arg) {
    struct connection *c = arg;
    int rbytes = 0;
    for (;;) {
        rbytes = read(c->fd, shared_rbuf, 1024 * 32);
        if (rbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                perror("Read error from client");
            }
        }
        if (rbytes < 4095)
            break; /* don't call read() again unless we may get data */
    }
}

static void client_handler(const int fd, const short which, void *arg) {
    struct connection *c = (struct connection *)arg;
    int err = 0;
    socklen_t errsize = sizeof(err);
    int written = 0;

    switch (c->state) {
    case conn_connecting:
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &errsize) < 0) {
            return;
        }
        if (err != 0) {
            return;
        }
        c->state = conn_sending;
        update_conn_event(c, EV_READ | EV_PERSIST);
    case conn_sending:
        if (which & EV_READ) {
            c->reader(c);
        } 
        if (which & EV_WRITE) {
            if (c->iov_towrite > 0)
                /* FIXME: Need to cuddle this from the writer or somefuck. */
                write_iovecs(c, conn_reading);
            if (c->iov_towrite <= 0)
                c->writer(c);
        }
        break;
    case conn_reading:
        c->reader(c);
        c->state = conn_sending;
        if (c->iov_towrite <= 0)
            c->writer(c);
        break;
    }
}

static int new_connection(struct connection *t)
{
    int sock;
    struct sockaddr_in dest_addr;
    int flags = 1;
    struct connection *c = (struct connection *)malloc(sizeof(struct connection));
    memcpy(c, t, sizeof(struct connection));

    sock = socket(AF_INET, SOCK_STREAM, 0);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(c->port_num);
    dest_addr.sin_addr.s_addr = inet_addr(c->ip_addr);

    if ( (flags = fcntl(sock, F_GETFL, 0)) < 0 ||
        fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        return -1;
    }

    memset(&(dest_addr.sin_zero), '\0', 8);

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

    if (connect(sock, (const struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
        if (errno != EINPROGRESS) {
            close(sock);
            return -1;
        }
    }

    c->fd = sock;
    c->state = conn_connecting;
    c->ev_flags = EV_WRITE;

    event_set(&c->ev, sock, c->ev_flags, client_handler, (void *)c);
    event_base_set(main_base, &c->ev);
    event_add(&c->ev, NULL);

    if (c->key_randomize) {
        c->cur_key = random() % c->key_count;
    }

    if (c->iov_count > 0) {
        c->vecs = calloc(c->iov_count, sizeof(struct iovec));
        if (c->vecs == NULL) {
            fprintf(stderr, "Couldn't allocate iovecs\n");
            exit(1);
        }
    }

    return sock;
}

static void init_bin_get(struct connection *t) {
    t->bin_get_pkt.message.header.request.magic = PROTOCOL_BINARY_REQ;
    t->bin_get_pkt.message.header.request.opcode = PROTOCOL_BINARY_CMD_GET;
    t->bin_get_pkt.message.header.request.keylen = 0; /* init to zero */
    t->bin_get_pkt.message.header.request.extlen = 0; /* no extras for gets */
    t->bin_get_pkt.message.header.request.bodylen = 0; /* init to zero */
    t->bin_get_pkt.message.header.request.opaque = 0; /* who cares */
    t->bin_get_pkt.message.header.request.cas = 0; /* also who cares */
}

static void init_bin_getq(struct connection *t) {
    /* lulz */
    init_bin_get(t);
    t->bin_get_pkt.message.header.request.opcode = PROTOCOL_BINARY_CMD_GETQ;
}

static void init_bin_set(struct connection *t) {
    t->bin_set_pkt.message.header.request.magic = PROTOCOL_BINARY_REQ;
    t->bin_set_pkt.message.header.request.opcode = PROTOCOL_BINARY_CMD_SET;
    t->bin_set_pkt.message.header.request.keylen = 0; /* init to zero */
    t->bin_set_pkt.message.header.request.extlen = 8; /* flags + exptime */
    t->bin_set_pkt.message.header.request.bodylen = 0; /* init to zero */
    t->bin_set_pkt.message.header.request.opaque = 0; /* who cares */
    t->bin_set_pkt.message.header.request.cas = 0; /* also who cares */

    t->bin_set_pkt.message.body.flags = 0;
    t->bin_set_pkt.message.body.expiration = 0; /* this will be an option */
}

static void init_bin_setq(struct connection *t) {
    init_bin_set(t);
    t->bin_set_pkt.message.header.request.opcode = PROTOCOL_BINARY_CMD_SETQ;
}

static void prealloc_keys(struct connection *t) {
    /* This "leaks" the blob on purpose. Also temporary hardcoded rough key
     * length is used. 
     */
    unsigned char *key_blob;
    unsigned char *key_blob_ptr;
    struct mc_key *keys;
    struct mc_key temp;
    uint64_t i;
    int x;
    int len = 0;
    long int rand_one;
    long int rand_two;

    /* Generate the blobs and key list */
    key_blob = calloc(t->key_count, 30);
    keys     = calloc(t->key_count, sizeof(struct mc_key));
    if (key_blob == NULL || keys == NULL) {
        perror("Mallocing key prealloc");
        exit(1);
    }
    key_blob_ptr = key_blob;
    fprintf(stdout, "Prealloc memory: %llu + %llu\n", (unsigned long long)(t->key_count) * 30,
        (unsigned long long)sizeof(struct mc_key) * (t->key_count));

    for (i = 0; i < t->key_count; i++) {
        len = sprintf(key_blob_ptr, "%s%llu", t->key_prefix,
            (unsigned long long)i);
        keys[i].key     = key_blob_ptr;
        keys[i].key_len = len;
        key_blob_ptr   += len;
    }

    t->keys = keys;

    /* Cool, now shuffle the key list if we need to */
    if (t->key_randomize == 0)
        return;

    /* TODO: Allow specifying the random seed */
    srandom(time(NULL));

    /* Run through the list once and shuffle */
    for (x = 0; x < 4; x++) {
    for (i = 0; i < t->key_count; i++) {
        rand_one = random() % t->key_count;
        rand_two = random() % t->key_count;
        temp = keys[rand_one];
        keys[rand_one] = keys[rand_two];
        keys[rand_two] = temp;
    }
    }
    /* in case you want to peek at the shuffling :P
    for (i = 0; i < t->key_count; i++) {
        fprintf(stdout, "Key: %.*s\n", (int)keys[i].key_len, keys[i].key);
    }*/
}

/* Get a little verbose to avoid a big if/else if tree */
static void parse_config_line(char *line) {
    char *in_progress, *token;
    struct connection template;
    int conns_tomake = 1;
    int newsock;
    int i;
    char *tmp;
    char *sender = NULL;

    enum {
        SEND = 0,
        RECV,
        TIME,
        USLEEP,
        COUNT,
        CONNS,
        SLEEP_EVERY,
        EXPIRE,
        KEY_PREFIX,
        KEY_LEN,
        KEY_GENERATE,
        VALUE_SIZE,
        VALUE_RANGE,
        VALUE_RANGE_STEP,
        MGET_COUNT,
        VALUE,
        RANDOMIZE,
        KEY_COUNT,
        KEY_PREALLOC,
        HOST,
        PORT
    };

    char *const key_options[] = {
        [SEND]             = "send",
        [RECV]             = "recv",
        [TIME]             = "time",
        [USLEEP]           = "usleep",
        [COUNT]            = "count",
        [CONNS]            = "conns",
        [SLEEP_EVERY]      = "sleep_every",
        [EXPIRE]           = "expire",
        [KEY_PREFIX]       = "key_prefix",
        [KEY_LEN]          = "key_len",
        [KEY_GENERATE]     = "key_generate",
        [VALUE_SIZE]       = "value_size",
        [VALUE_RANGE]      = "value_range",
        [VALUE_RANGE_STEP] = "value_range_step",
        [MGET_COUNT]       = "mget_count",
        [VALUE]            = "value",
        [RANDOMIZE]        = "key_randomize",
        [KEY_COUNT]        = "key_count",
        [KEY_PREALLOC]     = "key_prealloc",
        [HOST]             = "host",
        [PORT]             = "port",
        NULL
    };

    memset(&template, 0, sizeof(struct connection));
    /* Set defaults into template */
    strcpy(template.key_prefix, "foo");
    template.mget_count = 2;
    template.value_size = 2;
    template.value[0] = '\0';
    template.buf_written = 0;
    template.key_count = 200000;
    template.key_randomize = 0;
    template.key_prealloc = 1;
    strcpy(template.ip_addr, "127.0.0.1");
    template.port_num = 11211;

    /* Chomp the ending newline */
    tmp = rindex(line, '\n');
    if (tmp != NULL) 
        *tmp = '\0';
    while ((token = strtok_r(line, ",", &in_progress)) != NULL) {
        int key = 0;
        char *value = NULL;
        value = index(token, '=');
        *value = '\0';
        value++;
        
        line = NULL; /* lazy */
        while (key_options[key] != NULL) {
            if (strcmp(token, key_options[key]) == 0)
                break;
            key++;
        }
        fprintf(stderr, "id %d for key %s value %s\n", key, token, value);

        switch (key) {
        case SEND:
            sender = value;
            break;
        case RECV:
            template.reader = read_from_client;
            break;
        case CONNS:
            conns_tomake = atoi(value);
            break;
        case COUNT:
            break;
        case KEY_PREFIX:
            strcpy(template.key_prefix, value);
            break;
        case MGET_COUNT:
            template.mget_count = atoi(value);
            break;
        case VALUE_SIZE:
            template.value_size = atoi(value);
            break;
        case VALUE:
            strcpy(template.value, value);
            template.value_size = strlen(value);
            break;
        case RANDOMIZE:
            template.key_randomize = atoi(value);
            break;
        case KEY_COUNT:
            template.key_count = atoi(value);
            break;
        case KEY_PREALLOC:
            template.key_prealloc = atoi(value);
            break;
        case HOST:
            strcpy(template.ip_addr, value);
            break;
        case PORT:
            template.port_num = atoi(value);
            break;
        }
    }

    /* Gross double tree. Hey, it's string parsing in C! */
    if (template.key_prealloc) {
        prealloc_keys(&template);
        if (strcmp(sender, "ascii_get") == 0) {
            template.writer = prealloc_write_ascii_get_to_client;
            template.iov_count = 3;
        } else if (strcmp(sender, "ascii_mget") == 0) {
            template.writer = write_ascii_mget_to_client;
            template.iov_count = template.mget_count + 2;
        } else {
            fprintf(stderr, "Unknown command writer: %s", sender);
            exit(1);
        }
    } else {
        if (strcmp(sender, "ascii_set") == 0) {
            template.writer = write_ascii_set_to_client;
            template.iov_count = 3;
        } else if (strcmp(sender, "ascii_get") == 0) {
            template.writer = write_ascii_get_to_client;
        } else if (strcmp(sender, "ascii_mget") == 0) {
            template.writer = write_ascii_mget_to_client;
        } else if (strcmp(sender, "bin_get") == 0) {
            init_bin_get(&template);
            template.writer = write_bin_get_to_client;
        } else if (strcmp(sender, "bin_getq") == 0) {
            init_bin_getq(&template);
            template.writer = write_bin_getq_to_client;
        } else if (strcmp(sender, "bin_set") == 0) {
            init_bin_set(&template);
            template.writer = write_bin_set_to_client;
        } else if (strcmp(sender, "bin_setq") == 0) {
            init_bin_setq(&template);
            template.writer = write_bin_setq_to_client;
        } else {
            fprintf(stderr, "Unknown command writer: %s", sender);
            exit(1);
        }
    }

    for (i = 0; i < conns_tomake; i++) {
        newsock = new_connection(&template);
    }
}

int main(int argc, char **argv)
{
    FILE *cfd;
    char line[4096];
    counter = 1;
    reset_counter_after = 200000;

    shared_value = calloc(1024 * 1024, sizeof(unsigned char));

    main_base = event_init();

    cfd = fopen(argv[1], "r");
    if (cfd == NULL) {
        perror("Opening config file");
        exit(1);
    }

    while (fgets(line, 4096, cfd) != NULL) {
        parse_config_line(line);
    }

    event_base_loop(main_base, 0);
}
