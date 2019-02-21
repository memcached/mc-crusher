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
#include <stdbool.h>
#include <getopt.h>

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
#include <signal.h>

#include "protocol_binary.h"

#define SHARED_RBUF_SIZE 1024 * 64
#define SHARED_VALUE_SIZE 1024 * 1024

char host_default[NI_MAXHOST] = "127.0.0.1";
char port_num_default[NI_MAXSERV] = "11211";
int alarm_fired = 0;

enum conn_states {
    conn_connecting = 0,
    conn_sending,
    conn_reading,
    conn_sleeping,
};

struct mc_key {
    uint64_t key_offset;
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
    char host[NI_MAXHOST];
    char port_num[NI_MAXSERV];

    /* Event stuff */
    int fd;
    struct event ev;
    enum conn_states state;
    enum conn_states next_state;
    short ev_flags;

    /* Counters, bits, flags for individual senders/getters. */
    int mget_count;                /* # of ascii mget keys to send at once */
    unsigned char key_prefix[240];
    int value_size;
    int use_shared_value;
    unsigned char value[2048];     /* manually specified seed value */
    int buf_written;
    int buf_towrite;
    uint32_t expire;
    uint32_t flags;

    uint64_t pipelines; /* number of repeated commands per write */
    int usleep; /* us to sleep between write runs */
    uint64_t stop_after; /* run this many write events then stop */
    /* Buffers */
    uint64_t key_count;
    uint64_t key_blob_size;
    uint64_t key_randomize;
    uint64_t *cur_key;
    uint64_t *write_count;
    int      key_prealloc;
    struct mc_key *keys; // pointers into key_blob.
    unsigned char *key_blob;
    unsigned char wbuf[65536];
    unsigned char *wbuf_pos;

    /* time pacing */
    struct timeval next_sleep;
    struct timeval tosleep;
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
static void sleep_handler(const int fd, const short which, void *arg);
static void setup_thread(mc_thread *t);
static void create_thread(mc_thread *t);
static inline void run_write(struct connection *c);

static int update_conn_event(struct connection *c, const int new_flags)
{
    if (c->ev_flags == new_flags) return 2;
    if (event_del(&c->ev) == -1) return 0;

    c->ev_flags = new_flags;
    event_set(&c->ev, c->fd, new_flags, client_handler, (void *)c);
    event_base_set(c->t->base, &c->ev);

    if (event_add(&c->ev, 0) == -1) return 0;
    return 1;
}

static int update_conn_event_sleep(struct connection *c)
{
    struct timeval t = {.tv_sec = 0, .tv_usec = 0};
    struct timeval now;
    if (event_del(&c->ev) == -1) return 0;

    c->ev_flags = 0; // clear event flags in case we ping-pong to other modes
    evtimer_set(&c->ev, sleep_handler, (void *)c);
    event_base_set(c->t->base, &c->ev);

    gettimeofday(&now, NULL);

    // every time we come into this loop, we've run once. which means we
    // always have to advance the next_sleep timer.
    if (c->next_sleep.tv_sec == 0) {
        // initialize next_sleep as late as possible to avoid spamming.
        gettimeofday(&c->next_sleep, NULL);
    }
    memcpy(&t, &c->next_sleep, sizeof(struct timeval));
    timeradd(&t, &c->tosleep, &c->next_sleep);

    timersub(&c->next_sleep, &now, &t);
    // so far as I can tell, it treats times in the past as "Wake up
    // immediately".
    evtimer_add(&c->ev, &t);

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
            // the sender always checks for reads. not necessary to change?
            c->state = conn_sending;
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
        } else if (c->state == conn_sending) {
            update_conn_event(c, EV_READ | EV_WRITE | EV_PERSIST);
        } else if (c->state == conn_sleeping) {
            update_conn_event_sleep(c);
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
    ++*c->write_count;
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
    protocol_binary_request_set *pkt = (protocol_binary_request_set *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_SET;
    pkt->message.header.request.extlen = 8; /* flags + exptime */
    pkt->message.body.flags = htonl(c->flags);
    pkt->message.body.expiration = htonl(c->expire);

    struct iovec *vecs = c->vecs;
    int i = c->iov_used;
    vecs[i].iov_base = c->wbuf_pos;
    vecs[i].iov_len  = sizeof(protocol_binary_request_header) + 8;
    c->wbuf_pos += vecs[i].iov_len;
    c->iov_used++;
}

/* slightly crazy; since bin_prep_set changes wbuf_pos create the packet
 * pointer first, run original prep, then switch the command out.
 */
static void bin_prep_setq(struct connection *c) {
    protocol_binary_request_set *pkt = (protocol_binary_request_set *)c->wbuf_pos;
    bin_prep_set(c);
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_SETQ;
    // Continue to send since we don't expect to read anything.
    c->next_state = conn_sending;
}

static void bin_prep_touch(struct connection *c) {
    protocol_binary_request_touch *pkt = (protocol_binary_request_touch *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_TOUCH;
    pkt->message.header.request.extlen = 4; /* exptime */
    pkt->message.body.expiration = htonl(c->expire);

    struct iovec *vecs = c->vecs;
    int i = c->iov_used;
    vecs[i].iov_base = c->wbuf_pos;
    vecs[i].iov_len  = sizeof(protocol_binary_request_header) + 4;
    c->wbuf_pos += vecs[i].iov_len;
    c->iov_used++;
}

/* Unhappy with this, but it's still shorter/better than the old code.
 * Binprot is just unwieldy in C, or I haven't figured out how to use it
 * simply yet.
 */
static void bin_write_to_client(void *arg) {
    struct connection *c = arg;
    struct iovec *vecs = c->vecs;
    protocol_binary_request_header *pkt = (protocol_binary_request_header *)c->wbuf_pos;
    memset(pkt, 0, sizeof(protocol_binary_request_header));
    pkt->request.magic = PROTOCOL_BINARY_REQ;
    c->bin_prep_cmd(c);
    if (c->key_prealloc) {
        vecs[c->iov_used].iov_base = &c->key_blob[c->keys[*c->cur_key].key_offset];
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
        if (c->use_shared_value) {
            vecs[c->iov_used].iov_base = c->t->shared_value;
        } else {
            vecs[c->iov_used].iov_base = c->value;
        }
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
            vecs[i].iov_base = &c->key_blob[c->keys[*c->cur_key].key_offset];
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
    ret = sprintf(c->wbuf_pos, "set %s%llu %u %u %d\r\n", c->key_prefix,
            (unsigned long long)*c->cur_key, c->flags, c->expire, c->value_size);
    return ret;
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

static int ascii_delete_format(struct connection *c) {
    return sprintf(c->wbuf_pos, "delete %s%llu\r\n", c->key_prefix,
                (unsigned long long)*c->cur_key);
}

static void ascii_write_to_client(void *arg) {
    struct connection *c = arg;
    struct iovec *vecs = c->vecs;
    if (c->key_prealloc) {
        vecs[c->iov_used].iov_base = &c->key_blob[c->keys[*c->cur_key].key_offset];
        vecs[c->iov_used].iov_len  = c->keys[*c->cur_key].key_len;
    } else {
        vecs[c->iov_used].iov_base = c->wbuf_pos;
        vecs[c->iov_used].iov_len = c->ascii_format(c);
        c->wbuf_pos += vecs[c->iov_used].iov_len;
    }
    c->iov_used++;
    if (c->value_size) {
        if (c->use_shared_value) {
            vecs[c->iov_used].iov_base = c->t->shared_value;
        } else {
            vecs[c->iov_used].iov_base = c->value;
        }
        vecs[c->iov_used].iov_len = c->value_size;
        c->iov_used++;
        vecs[c->iov_used].iov_base = "\r\n";
        vecs[c->iov_used].iov_len = 2;
        c->iov_used++;
    }
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

static void sleep_handler(const int fd, const short which, void *arg) {
    struct connection *c = (struct connection *)arg;
    c->next_state = conn_sleeping;
    c->reader(c);
    run_write(c);
}

static inline void run_write(struct connection *c) {
    int i;
    c->wbuf_pos = c->wbuf;
    c->iov_used = 0;
    for (i = 0; i < c->pipelines; i++) {
        c->writer(c);
    }
    c->iov_towrite = sum_iovecs(c->vecs, c->iov_used);
    write_iovecs(c, c->next_state);
    if (c->stop_after && *c->write_count >= c->stop_after) {
        event_del(&c->ev);
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
                write_iovecs(c, c->next_state);
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

#define U_PER_S 1000000
static void timeval_split(const uint64_t in, long int *outs, long int *outu) {
    if (in >= U_PER_S) {
        *outs = in / U_PER_S;
        *outu = in - (*outs * U_PER_S);
    } else {
        *outs = 0;
        *outu = in;
    }
}

static int new_connection(struct connection *t)
{
    int sock;
    struct addrinfo *ai;
    struct addrinfo *ai_next;
    struct addrinfo hints = { .ai_flags = AI_PASSIVE,
                              .ai_family = AF_UNSPEC };
    int flags = 1;
    int error;
    struct connection *c = (struct connection *)malloc(sizeof(struct connection));
    memcpy(c, t, sizeof(struct connection));

    error = getaddrinfo(c->host, c->port_num, &hints, &ai);
    if (error != 0) {
        if (error != EAI_SYSTEM) {
            fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
        } else {
            perror("getaddrinfo()");
        }
        freeaddrinfo(ai);
        return -1;
    }

    for (ai_next = ai; ai_next; ai_next = ai_next->ai_next) {
        sock = socket(ai_next->ai_family, ai_next->ai_socktype, ai_next->ai_protocol);
        if (sock == -1) {
            perror("socket");
            continue;
        } else {
            break;
        }
    }

    if (sock < 0) {
        fprintf(stderr, "getaddrinfo failed to provide any valid addresses: %s[%s]\n",
                c->host, c->port_num);
        freeaddrinfo(ai);
        return -1;
    }

    if ( (flags = fcntl(sock, F_GETFL, 0)) < 0 ||
        fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        freeaddrinfo(ai);
        return -1;
    }

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

    if (connect(sock, ai_next->ai_addr, ai_next->ai_addrlen) == -1) {
        if (errno != EINPROGRESS) {
            close(sock);
            freeaddrinfo(ai);
            return -1;
        }
    }

    freeaddrinfo(ai);
    c->fd = sock;
    c->state = conn_connecting;
    c->ev_flags = EV_WRITE;

    if (c->usleep) {
        // spread out the initial wakeup times
        long int initsleep = random() % c->usleep;
        long int initsleep_s = 0;
        timeval_split(c->usleep, &c->tosleep.tv_sec, &c->tosleep.tv_usec);
        timeval_split(initsleep, &initsleep_s, &initsleep);
        struct timeval t = {.tv_sec = initsleep_s, .tv_usec = initsleep};
        evtimer_set(&c->ev, sleep_handler, (void *)c);
        event_base_set(c->t->base, &c->ev);
        evtimer_add(&c->ev, &t);
    } else{
        event_set(&c->ev, sock, c->ev_flags, client_handler, (void *)c);
        event_base_set(c->t->base, &c->ev);
        event_add(&c->ev, NULL);
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

// TODO: use a header line or meta file to determine when the file's changed.
static bool load_keys(struct connection *t, const char *file) {
    size_t index_size = sizeof(struct mc_key) * t->key_count;
    size_t key_blob_size = 0;
    char ptmp[1024];
    struct stat statbuf;

    snprintf(ptmp, 1023, "%s.idx", file);
    FILE *ki = fopen(ptmp, "r");
    if (ki == NULL) {
        perror("Failed to open key index file for reading\n");
        return false;
    }

    t->keys = malloc(index_size);
    if (t->keys == NULL) {
        fprintf(stderr, "Failed to malloc space for key index\n");
        exit(1);
    }

    fprintf(stdout, "Loading key index file of size: %lu\n", index_size);
    {
        size_t read = fread(t->keys, 1, index_size, ki);
        if (read < index_size) {
            fprintf(stderr, "Failed to read key index file\n");
            exit(1);
        }
    }
    fclose(ki);

    // key blob file size is unknown, so we ask the filesystem.
    snprintf(ptmp, 1023, "%s.keys", file);
    if (stat(ptmp, &statbuf) != 0) {
        perror("Failed to stat key blob file");
        return false;
    }

    key_blob_size = statbuf.st_size;

    FILE *kf = fopen(ptmp, "r");
    if (kf == NULL) {
        perror("Failed to open key blob file for reading");
        exit(1);
    }

    t->key_blob_size = key_blob_size;
    t->key_blob = malloc(key_blob_size);
    if (t->key_blob == NULL) {
        fprintf(stderr, "Failed to malloc space for key blob\n");
        exit(1);
    }

    fprintf(stdout, "Loading key blob file of size: %lu\n", key_blob_size);
    {
        size_t read = fread(t->key_blob, 1, key_blob_size, kf);
        if (read < key_blob_size) {
            fprintf(stderr, "Failed to read key blob file\n");
            exit(1);
        }
    }

    fclose(kf);
    return true;
}

// FIXME: could put it all in one file since key index size is known?
static void write_keys(const struct connection *t, const char *file) {
    size_t index_size = sizeof(struct mc_key) * t->key_count;
    size_t key_blob_size = t->key_blob_size;
    char ptmp[1024];

    snprintf(ptmp, 1023, "%s.idx", file);
    FILE *ki = fopen(ptmp, "w");
    if (ki == NULL) {
        perror("Failed to open key index file for writing");
        exit(1);
    }

    {
        size_t written = fwrite(t->keys, 1, index_size, ki);
        if (written < index_size) {
            // TODO: how to actually use ferror?
            fprintf(stderr, "failed to write data to key index file\n");
            exit(1);
        }
    }
    fclose(ki);

    snprintf(ptmp, 1023, "%s.keys", file);
    FILE *kf = fopen(ptmp, "w");
    if (kf == NULL) {
        perror("Failed to open key blob file for writing");
        exit(1);
    }

    {
        size_t written = fwrite(t->key_blob, 1, key_blob_size, kf);
        if (written < key_blob_size) {
            // TODO: how to actually use ferror?
            fprintf(stderr, "failed to write data to key blob file\n");
            exit(1);
        }
    }
    fclose(kf);
}

static void prealloc_keys(struct connection *t, const size_t key_blob_size) {
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
    uint64_t used = 0;
    long int rand_one;
    long int rand_two;
    char *fmt;

    /* Generate the blobs and key list */
    if (key_blob_size != 0) {
        key_blob = calloc(key_blob_size, sizeof(char));
        t->key_blob_size = key_blob_size;
    } else {
        key_blob = calloc(t->key_count, 60);
        t->key_blob_size = t->key_count * 60;
    }
    keys     = calloc(t->key_count, sizeof(struct mc_key));
    if (key_blob == NULL || keys == NULL) {
        perror("Mallocing key prealloc");
        exit(1);
    }
    key_blob_ptr = key_blob;
    fprintf(stdout, "Prealloc memory: %llu + %llu\n", (unsigned long long)(t->key_blob_size),
        (unsigned long long)sizeof(struct mc_key) * (t->key_count));

    // Make the formatter think it's writing into wbuf.
    t->wbuf_pos = key_blob_ptr;
    for (i = 0; i < t->key_count; i++) {
        len = t->prealloc_format(t);
        keys[i].key_offset = used;
        keys[i].key_len = len;
        t->wbuf_pos    += len;
        used += len;
        run_counter(t);
    }
    t->wbuf_pos = t->wbuf;
    *t->cur_key = 0;

    t->keys = keys;
    t->key_blob = key_blob;
    t->key_blob_size = used;

    fprintf(stdout, "key_blob used: %llu\n", (unsigned long long)used);

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
static void parse_config_line(mc_thread *main_thread, char *line, bool keygen) {
    char *in_progress, *token;
    struct connection template;
    int conns_tomake = 1;
    int newsock;
    int i;
    char *tmp;
    char *sender = NULL;
    int add_space = 0;
    int new_thread = 0;
    char key_file[1024];

    enum {
        SEND = 0,
        RECV,
        TIME,
        USLEEP,
        COUNT,
        CONNS,
        EXPIRE,
        FLAGS,
        KEY_PREFIX,
        KEY_LEN,
        KEY_GENERATE,
        VALUE_SIZE,
        VALUE_RANGE,
        VALUE_RANGE_STEP,
        MGET_COUNT,
        VALUE,
        RANDOMIZE,
        STOP_AFTER,
        KEY_COUNT,
        KEY_BLOB_SIZE,
        KEY_PREALLOC,
        KEY_FILE,
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
        [EXPIRE]           = "expire",
        [FLAGS]            = "flags",
        [KEY_PREFIX]       = "key_prefix",
        [KEY_LEN]          = "key_len",
        [KEY_GENERATE]     = "key_generate",
        [VALUE_SIZE]       = "value_size",
        [VALUE_RANGE]      = "value_range",
        [VALUE_RANGE_STEP] = "value_range_step",
        [MGET_COUNT]       = "mget_count",
        [VALUE]            = "value",
        [RANDOMIZE]        = "key_randomize",
        [STOP_AFTER]       = "stop_after",
        [KEY_COUNT]        = "key_count",
        [KEY_BLOB_SIZE]    = "key_blob_size",
        [KEY_PREALLOC]     = "key_prealloc",
        [KEY_FILE]         = "key_file",
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
    template.use_shared_value = 1;
    template.buf_written = 0;
    template.key_count = 200000;
    template.key_blob_size = 0;
    template.key_randomize = 0;
    template.key_prealloc = 1;
    template.pipelines = 1;
    template.expire = 0;
    template.flags = 0;
    strcpy(template.host, host_default);
    strcpy(template.port_num, port_num_default);
    template.next_state = conn_reading;
    template.cur_key = (uint64_t *)malloc(sizeof(uint64_t));
    template.write_count = (uint64_t *)malloc(sizeof(uint64_t));
    *template.cur_key = 0;
    *template.write_count = 0;

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
        case EXPIRE:
            // TODO: import strtoul wrappers
            template.expire = atoi(value);
            break;
        case FLAGS:
            template.flags = atoi(value);
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
            template.use_shared_value = 0;
            break;
        case RANDOMIZE:
            template.key_randomize = atoi(value);
            break;
        case STOP_AFTER:
            template.stop_after = atoi(value);
            break;
        case KEY_COUNT:
            template.key_count = atoi(value);
            break;
        case KEY_BLOB_SIZE:
            template.key_blob_size = atoi(value);
            break;
        case KEY_PREALLOC:
            template.key_prealloc = atoi(value);
            break;
        case KEY_FILE:
            strcpy(key_file, value);
            break;
        case HOST:
            strcpy(template.host, value);
            break;
        case PORT:
            strcpy(template.port_num, value);
            break;
        case USLEEP:
            template.usleep = atoi(value);
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
        template.iov_count = 3;
    } else if (strcmp(sender, "ascii_mget") == 0) {
        template.writer = ascii_write_mget_to_client;
        template.iov_count = template.mget_count + 2;
        template.prealloc_format = ascii_mget_format;
    } else if (strcmp(sender, "ascii_incr") == 0) {
        template.writer = ascii_write_to_client;
        template.ascii_format = ascii_incr_format;
    } else if (strcmp(sender, "ascii_delete") == 0) {
        template.writer = ascii_write_to_client;
        template.ascii_format = ascii_delete_format;
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
    } else if (strcmp(sender, "bin_touch") == 0) {
        template.writer = bin_write_to_client;
        template.bin_prep_cmd = bin_prep_touch;
        template.bin_format = bin_key_format;
        template.prealloc_format = bin_key_format;
        template.iov_count = 2;
    } else {
        fprintf(stderr, "Unknown command writer: %s\n", sender);
        exit(1);
    }

    if (template.key_prealloc) {
        bool have_keys = false;
        if (!template.prealloc_format) {
            template.prealloc_format = template.ascii_format;
        }
        if (key_file != NULL) {
            have_keys = load_keys(&template, key_file);
        }

        // FIXME: just fetch key_blob_size from the template?
        if (!have_keys) {
            prealloc_keys(&template, template.key_blob_size);
        }

        if (!have_keys && key_file != NULL) {
            write_keys(&template, key_file);
        }
    }
    // FIXME: Should use iov_count for prealloc, iov_used for writers.
    template.iov_count = template.iov_count * template.pipelines;

    // don't actually do anything if we're just here to pre-generate keys
    if (keygen) {
        return;
    }

    for (i = 0; i < conns_tomake; i++) {
        newsock = new_connection(&template);
        if (newsock < 0) {
            fprintf(stderr, "Failed to connect: %s[%s]\n", template.host, template.port_num);
            exit(1);
        }
    }
    if (new_thread) {
        create_thread(template.t);
    }
}

static void *thread_runner(void *arg) {
    mc_thread *t = arg;
    int ret = event_base_loop(t->base, 0);
    fprintf(stderr, "Thread exiting: %d\n", ret);
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

static void alarm_handler(int signal) {
    alarm_fired = 1;
}

int main(int argc, char **argv)
{
    FILE *cfd = NULL;
    char line[4096];
    int timeout = 0;
    bool keygen = false; // exit after reading configuration.
    // kill buffering of stdout so a parent process can monitor it.
    setvbuf(stdout, NULL, _IONBF, 0);
    mc_thread *main_thread = NULL;
    main_thread = calloc(1, sizeof(mc_thread));
    setup_thread(main_thread);

    const struct option longopts[] = {
        // standard operational options
        {"ip", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"conf", required_argument, 0, 'c'},
        {"timeout", required_argument, 0, 't'},
        // keygen mode. exits after generating key files.
        {"keygen", no_argument, 0, 'k'},
        // end of options.
        {0, 0, 0, 0}
    };
    int optindex;
    int c;
    while (-1 != (c = getopt_long(argc, argv, "", longopts, &optindex))) {
        switch (c) {
        case 'i':
            strncpy(host_default, optarg, NI_MAXHOST);
            printf("ip address default: %s\n", host_default);
            break;
        case 'p':
            strncpy(port_num_default, optarg, NI_MAXSERV);
            printf("port default: %s\n", port_num_default);
            break;
        case 'c':
            cfd = fopen(optarg, "r");
            if (cfd == NULL) {
                perror("Opening config file");
                exit(1);
            }
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'k':
            keygen = true;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
        }
    }

    if (cfd == NULL) {
        fprintf(stderr, "error: use --conf [file] to specify a config file\n");
        exit(1);
    }

    while (fgets(line, 4096, cfd) != NULL) {
        parse_config_line(main_thread, line, keygen);
    }
    fclose(cfd);

    if (!keygen) {
        create_thread(main_thread);
    }

    if (timeout != 0) {
        struct sigaction sig_h;

        sig_h.sa_handler = alarm_handler;
        sig_h.sa_flags = 0;

        sigaction(SIGALRM, &sig_h, NULL);
        fprintf(stderr, "setting a timeout\n");
        alarm(timeout);
    }
    // TODO: Fire a signal at parent when threads exit? since they shouldn't.
    printf("done initializing\n");
    if (!keygen) {
        pause();
    }
    if (alarm_fired) {
        printf("timed run complete\n");
    }
    return 0;
}
