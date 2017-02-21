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

#define SHARED_RBUF_SIZE 1024 * 64
#define SHARED_VALUE_SIZE 1024 * 1024

char ip_addr_default[60] = "127.0.0.1";
int port_num_default = 11211;

enum conn_states {
    conn_connecting = 0,
    conn_sending,
    conn_reading,
};

struct mc_key {
    unsigned char *key;
    size_t key_len;
};

typedef struct _mc_thread {
    pthread_t thread_id;
    struct event_base *base;
    unsigned char *shared_value;
    unsigned char *shared_rbuf;
} mc_thread;

struct connection {
    /* Owner thread */
    mc_thread *t;

    /* host */
    char ip_addr[60];
    int port_num;

    /* Event stuff */
    int fd;
    struct event ev;
    enum conn_states state;
    short ev_flags;

    /* Counters, bits, flags for individual senders/getters. */
    int mget_count;                /* # of ascii mget keys to send at once */
    unsigned char key_prefix[240];
    int value_size;
    unsigned char value[2048];     /* manually specified seed value */
    int buf_written;
    int buf_towrite;

    /* Buffers */
    uint64_t pipelines; /* number of repeated commands per write */
    uint64_t key_count;
    uint64_t key_randomize;
    uint64_t *cur_key;
    int      key_prealloc;
    struct mc_key *keys;
    unsigned char wbuf[65536];
    unsigned char *wbuf_pos;

    /* iovectors */
    struct iovec *vecs;
    int    iov_used; /* iovecs used so far */
    int    iov_count; /* iovecs in total */
    int    iov_towrite; /* bytes to write */

    /* reader/writer function pointers */
    void (*writer)(void *arg);
    void (*reader)(void *arg);

    /* helper function specific to the generic ascii writer */
    int (*ascii_format)(struct connection *c);
    int (*bin_format)(struct connection *c);
    void (*bin_prep_cmd)(struct connection *c);
    int (*prealloc_format)(struct connection *c);
};

static void client_handler(const int fd, const short which, void *arg);
static void setup_thread(mc_thread *t);
static void create_thread(mc_thread *t);

static int update_conn_event(struct connection *c, const int new_flags)
{
    if (c->ev_flags == new_flags) return 1;
    if (event_del(&c->ev) == -1) return 0;

    c->ev_flags = new_flags;
    event_set(&c->ev, c->fd, new_flags, client_handler, (void *)c);
    event_base_set(c->t->base, &c->ev);

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
            update_conn_event(c, EV_READ | EV_WRITE | EV_PERSIST);
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
        //fprintf(stderr, "Draining iovecs to %d (%d)\n", c->iov_towrite, written);
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
    if (++*c->cur_key >= c->key_count) {
        //fprintf(stdout, "Did %llu writes\n", (unsigned long long)c->key_count);
        *c->cur_key = 0;
    }
}

/* === BINARY PROTOCOL === */

static int bin_key_format(struct connection *c) {
    return sprintf(c->wbuf_pos, "%s%llu", c->key_prefix,
            (unsigned long long)*c->cur_key);
}

// can generalize this a bit further.
static void bin_prep_getq(struct connection *c) {
    protocol_binary_request_get *pkt = (protocol_binary_request_get *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_GETQ;

    struct iovec *vecs = c->vecs;
    int i = c->iov_used;
    vecs[i].iov_base = c->wbuf_pos;
    vecs[i].iov_len  = sizeof(protocol_binary_request_get);
    c->wbuf_pos += vecs[i].iov_len;
    c->iov_used++;
}

static void bin_prep_get(struct connection *c) {
    protocol_binary_request_get *pkt = (protocol_binary_request_get *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_GET;

    struct iovec *vecs = c->vecs;
    int i = c->iov_used;
    vecs[i].iov_base = c->wbuf_pos;
    vecs[i].iov_len  = sizeof(protocol_binary_request_get);
    c->wbuf_pos += vecs[i].iov_len;
    c->iov_used++;
}

static void bin_prep_set(struct connection *c) {
    protocol_binary_request_get *pkt = (protocol_binary_request_get *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_SET;
    pkt->message.header.request.extlen = 8; /* flags + exptime */

    struct iovec *vecs = c->vecs;
    int i = c->iov_used;
    vecs[i].iov_base = c->wbuf_pos;
    vecs[i].iov_len  = sizeof(protocol_binary_request_set);
    c->wbuf_pos += vecs[i].iov_len;
    c->iov_used++;
}

/* slightly crazy; since bin_prep_set changes wbuf_pos create the packet
 * pointer first, run original prep, then switch the command out.
 */
static void bin_prep_setq(struct connection *c) {
    protocol_binary_request_get *pkt = (protocol_binary_request_get *)c->wbuf_pos;
    bin_prep_set(c);
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_SETQ;
}

/* Unhappy with this, but it's still shorter/better than the old code.
 * Binprot is just unwieldy in C, or I haven't figured out how to use it
 * simply yet.
 */
/* FIXME: There's a bug when setting a large pipeline count (20-50) for
 * binprot commands (could be others too). Connections seem to die off. */
/* FIXME: SETQ doesn't work since it needs to stay in sending mode post-write,
 * and the top level writer is hardcoded to swap to reader right now. */
static void bin_write_to_client(void *arg) {
    struct connection *c = arg;
    struct iovec *vecs = c->vecs;
    protocol_binary_request_header *pkt = (protocol_binary_request_header *)c->wbuf_pos;
    memset(pkt, 0, sizeof(protocol_binary_request_header));
    pkt->request.magic = PROTOCOL_BINARY_REQ;
    c->bin_prep_cmd(c);
    if (c->key_prealloc) {
        vecs[c->iov_used].iov_base = c->keys[*c->cur_key].key;
        vecs[c->iov_used].iov_len  = c->keys[*c->cur_key].key_len;
    } else {
        vecs[c->iov_used].iov_base = c->wbuf_pos;
        vecs[c->iov_used].iov_len = c->bin_format(c);
        c->wbuf_pos += vecs[c->iov_used].iov_len;
    }
    int bodylen = vecs[c->iov_used].iov_len + pkt->request.extlen;
    pkt->request.keylen = htons(vecs[c->iov_used].iov_len);
    c->iov_used++;
    if (c->value_size) {
        bodylen += c->value_size;
        vecs[c->iov_used].iov_base = c->value;
        vecs[c->iov_used].iov_len = c->value_size;
        c->iov_used++;
    }
    pkt->request.bodylen = htonl(bodylen);
    run_counter(c);
}

/* === ASCII PROTOCOL TESTS === */

static int ascii_mget_format(struct connection *c) {
    return sprintf(c->wbuf_pos, "%s%llu ", c->key_prefix,
            (unsigned long long)*c->cur_key);
}

/* Multigets have a weird/specific format. */
static void ascii_write_mget_to_client(void *arg) {
    struct connection *c = arg;
    int i;
    struct iovec *vecs = c->vecs;
    vecs[0].iov_base = "get ";
    vecs[0].iov_len  = 4;
    for (i = 1; i < c->mget_count + 1; i++) {
        if (c->key_prealloc) {
            vecs[i].iov_base = c->keys[*c->cur_key].key;
            vecs[i].iov_len  = c->keys[*c->cur_key].key_len;
        } else {
            vecs[i].iov_base = c->wbuf_pos;
            vecs[i].iov_len  = ascii_mget_format(c);
        }
        run_counter(c);
    }
    vecs[i].iov_base = "\r\n";
    vecs[i].iov_len  = 2;
}

static int ascii_set_format(struct connection *c) {
    int ret = 0;
    ret = sprintf(c->wbuf_pos, "set %s%llu 0 0 %d\r\n", c->key_prefix,
            (unsigned long long)*c->cur_key, c->value_size);
    memcpy(c->wbuf_pos + ret, c->value, c->value_size);
    memcpy(c->wbuf_pos + ret + c->value_size, "\r\n", 2);
    return ret + c->value_size + 2;
}

static int ascii_incr_format(struct connection *c) {
    return sprintf(c->wbuf_pos, "incr %s%llu 1\r\n", c->key_prefix,
                (unsigned long long)*c->cur_key);
}

static int ascii_decr_format(struct connection *c) {
    return sprintf(c->wbuf_pos, "decr %s%llu 1\r\n", c->key_prefix,
                (unsigned long long)*c->cur_key);
}

static int ascii_get_format(struct connection *c) {
    return sprintf(c->wbuf_pos, "get %s%llu\r\n", c->key_prefix,
                (unsigned long long)*c->cur_key);
}

static void ascii_write_to_client(void *arg) {
    struct connection *c = arg;
    struct iovec *vecs = c->vecs;
    if (c->key_prealloc) {
        vecs[c->iov_used].iov_base = c->keys[*c->cur_key].key;
        vecs[c->iov_used].iov_len  = c->keys[*c->cur_key].key_len;
    } else {
        vecs[c->iov_used].iov_base = c->wbuf_pos;
        vecs[c->iov_used].iov_len = c->ascii_format(c);
        c->wbuf_pos += vecs[c->iov_used].iov_len;
    }
    c->iov_used++;
    run_counter(c);
}

/* === READERS === */

static void read_from_client(void *arg) {
    struct connection *c = arg;
    int rbytes = 0;
    for (;;) {
        rbytes = read(c->fd, c->t->shared_rbuf, 1024 * 32);
        if (rbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                perror("Read error from client");
            }
        }
        if (rbytes < 2096)
            break; /* don't call read() again unless we may get data */
    }
}

/* === HANDLERS === */

static inline void run_write(struct connection *c) {
    int i;
    c->wbuf_pos = c->wbuf;
    c->iov_used = 0;
    for (i = 0; i < c->pipelines; i++) {
        c->writer(c);
    }
    c->iov_towrite = sum_iovecs(c->vecs, c->iov_used);
    write_iovecs(c, conn_reading);
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
                /* FIXME: Create a c->next_state or similar */
                write_iovecs(c, conn_reading);
            if (c->iov_towrite <= 0) {
                run_write(c);
            }
        }
        break;
    case conn_reading:
        c->reader(c);
        c->state = conn_sending;
        if (c->iov_towrite <= 0)
            run_write(c);
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
    event_base_set(c->t->base, &c->ev);
    event_add(&c->ev, NULL);

    if (c->iov_count > 0) {
        c->vecs = calloc(c->iov_count, sizeof(struct iovec));
        if (c->vecs == NULL) {
            fprintf(stderr, "Couldn't allocate iovecs\n");
            exit(1);
        }
    }

    return sock;
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
    char *fmt;

    /* Generate the blobs and key list */
    key_blob = calloc(t->key_count, 60);
    keys     = calloc(t->key_count, sizeof(struct mc_key));
    if (key_blob == NULL || keys == NULL) {
        perror("Mallocing key prealloc");
        exit(1);
    }
    key_blob_ptr = key_blob;
    fprintf(stdout, "Prealloc memory: %llu + %llu\n", (unsigned long long)(t->key_count) * 60,
        (unsigned long long)sizeof(struct mc_key) * (t->key_count));

    // Make the formatter think it's writing into wbuf.
    t->wbuf_pos = key_blob_ptr;
    for (i = 0; i < t->key_count; i++) {
        len = t->prealloc_format(t);
        keys[i].key     = t->wbuf_pos;
        keys[i].key_len = len;
        t->wbuf_pos    += len;
        run_counter(t);
    }
    t->wbuf_pos = t->wbuf;
    *t->cur_key = 0;

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
static void parse_config_line(mc_thread *main_thread, char *line) {
    char *in_progress, *token;
    struct connection template;
    int conns_tomake = 1;
    int newsock;
    int i;
    char *tmp;
    char *sender = NULL;
    int add_space = 0;
    int new_thread = 0;

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
        PORT,
        THREAD,
        PIPELINES
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
        [THREAD]           = "thread",
        [PIPELINES]        = "pipelines",
        NULL
    };


    memset(&template, 0, sizeof(struct connection));
    /* Set defaults into template */
    strcpy(template.key_prefix, "foo");
    template.t = main_thread;
    template.mget_count = 2;
    template.value_size = 0;
    template.value[0] = '\0';
    template.buf_written = 0;
    template.key_count = 200000;
    template.key_randomize = 0;
    template.key_prealloc = 1;
    template.pipelines = 1;
    strcpy(template.ip_addr, ip_addr_default);
    template.port_num = port_num_default;
    template.cur_key = (uint64_t *)malloc(sizeof(uint64_t));
    *template.cur_key = 0;

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
        case THREAD:
            template.t = calloc(1, sizeof(mc_thread));
            setup_thread(template.t);
            new_thread = 1;
            break;
        case PIPELINES:
            template.pipelines = atoi(value);
            break;
        }
    }

    template.iov_count = 1;
    if (strcmp(sender, "ascii_get") == 0) {
        template.writer = ascii_write_to_client;
        template.ascii_format = ascii_get_format;
    } else if (strcmp(sender, "ascii_set") == 0) {
        template.writer = ascii_write_to_client;
        template.ascii_format = ascii_set_format;
    } else if (strcmp(sender, "ascii_mget") == 0) {
        template.writer = ascii_write_mget_to_client;
        template.iov_count = template.mget_count + 2;
        template.prealloc_format = ascii_mget_format;
    } else if (strcmp(sender, "ascii_incr") == 0) {
        template.writer = ascii_write_to_client;
        template.ascii_format = ascii_incr_format;
    } else if (strcmp(sender, "ascii_decr") == 0) {
        template.writer = ascii_write_to_client;
        template.ascii_format = ascii_decr_format;
    } else if (strcmp(sender, "bin_get") == 0) {
        template.writer = bin_write_to_client;
        template.bin_prep_cmd = bin_prep_get;
        template.bin_format = bin_key_format;
        template.prealloc_format = bin_key_format;
        template.iov_count = 2;
    } else if (strcmp(sender, "bin_getq") == 0) {
        template.writer = bin_write_to_client;
        template.bin_prep_cmd = bin_prep_getq;
        template.bin_format = bin_key_format;
        template.prealloc_format = bin_key_format;
        template.iov_count = 2;
    } else if (strcmp(sender, "bin_set") == 0) {
        template.writer = bin_write_to_client;
        template.bin_prep_cmd = bin_prep_set;
        template.bin_format = bin_key_format;
        template.prealloc_format = bin_key_format;
        template.iov_count = 3;
    } else if (strcmp(sender, "bin_setq") == 0) {
        template.writer = bin_write_to_client;
        template.bin_prep_cmd = bin_prep_setq;
        template.bin_format = bin_key_format;
        template.prealloc_format = bin_key_format;
        template.iov_count = 3;
    } else {
        fprintf(stderr, "Unknown command writer: %s\n", sender);
        exit(1);
    }

    if (template.key_prealloc) {
        if (!template.prealloc_format) {
            template.prealloc_format = template.ascii_format;
        }
        prealloc_keys(&template);
    }
    // FIXME: Should use iov_count for prealloc, iov_used for writers.
    template.iov_count = template.iov_count * template.pipelines;

    for (i = 0; i < conns_tomake; i++) {
        newsock = new_connection(&template);
    }
    if (new_thread) {
        create_thread(template.t);
    }
}

static void *thread_runner(void *arg) {
    mc_thread *t = arg;
    event_base_loop(t->base, 0);
    fprintf(stderr, "Thread exiting\n");
    return NULL;
}

static void setup_thread(mc_thread *t) {
    t->base = event_init();
    if (!t->base) {
        fprintf(stderr, "Cannot allocate event base\n");
        exit(1);
    }

    t->shared_value = calloc(SHARED_VALUE_SIZE, sizeof(unsigned char));
    t->shared_rbuf = calloc(SHARED_RBUF_SIZE, sizeof(unsigned char));
}

static void create_thread(mc_thread *t) {
    pthread_attr_t attr;
    int ret;

    pthread_attr_init(&attr);
    if ((ret = pthread_create(&t->thread_id, &attr, thread_runner, t)) != 0) {
        fprintf(stderr, "Cannot create thread: %s\n", strerror(ret));
        exit(1);
    }
}

int main(int argc, char **argv)
{
    FILE *cfd;
    char line[4096];
    mc_thread *main_thread = NULL;
    main_thread = calloc(1, sizeof(mc_thread));
    setup_thread(main_thread);

    if (argc > 2) {
        strncpy(ip_addr_default, argv[2], 60);
        printf("ip address default: %s\n", ip_addr_default);
    }
    if (argc > 3) {
        port_num_default = atoi(argv[3]);
        printf("port default: %d\n", port_num_default);
    }

    cfd = fopen(argv[1], "r");
    if (cfd == NULL) {
        perror("Opening config file");
        exit(1);
    }

    while (fgets(line, 4096, cfd) != NULL) {
        parse_config_line(main_thread, line);
    }
    fclose(cfd);

    create_thread(main_thread);
    pthread_join(main_thread->thread_id, NULL);
    return 0;
}
