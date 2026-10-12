// Minimal C shim over Network.framework UDP for use as a QUIC datagram
// transport: a listener whose peers become flows, or one client flow.
// Callbacks run on a dispatch queue owned by the handle.
#include <Network/Network.h>
#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

typedef void (*nwudp_recv_cb)(void *ctx, uint64_t flow, const void *data, size_t len);
typedef void (*nwudp_flow_cb)(void *ctx, uint64_t flow, const struct sockaddr *remote,
                              const struct sockaddr *local);
typedef void (*nwudp_close_cb)(void *ctx, uint64_t flow);

#define NWUDP_MAX_UNPROTECTED_FLOWS 128
#define NWUDP_UNPROTECTED_IDLE_NS (3ULL * 1000 * 1000 * 1000)

typedef struct flow {
    uint64_t id;
    nw_connection_t conn;
    bool ready;
    bool protected;
    uint64_t last_activity;
    // datagrams queued before the flow is ready
    dispatch_data_t pending[64];
    int npending;
} flow_t;

typedef struct nwudp {
    void *ctx;
    nwudp_flow_cb on_flow;
    nwudp_recv_cb on_recv;
    nwudp_close_cb on_close;
    dispatch_queue_t queue;
    nw_listener_t listener;
    pthread_mutex_t lock;
    flow_t **flows;
    size_t nflows, cap;
    size_t max_unprotected_flows;
    uint64_t next_id;
    dispatch_source_t reaper;
} nwudp_t;

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static nw_parameters_t udp_params(void) {
    nw_parameters_t p = nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                        NW_PARAMETERS_DEFAULT_CONFIGURATION);
    nw_parameters_set_reuse_local_address(p, true);
    return p;
}

static flow_t *find_flow(nwudp_t *h, uint64_t id) {
    for (size_t i = 0; i < h->nflows; i++)
        if (h->flows[i]->id == id) return h->flows[i];
    return NULL;
}

static flow_t *take_flow(nwudp_t *h, uint64_t id) {
    for (size_t i = 0; i < h->nflows; i++) {
        if (h->flows[i]->id == id) {
            flow_t *f = h->flows[i];
            h->flows[i] = h->flows[--h->nflows];
            return f;
        }
    }
    return NULL;
}

static dispatch_data_t copy_datagram(nwudp_t *h, const void *data, size_t len) {
    void *copy = malloc(len);
    if (!copy) return NULL;
    memcpy(copy, data, len);
    return dispatch_data_create(copy, len, h->queue, DISPATCH_DATA_DESTRUCTOR_FREE);
}

static void destroy_flow(nwudp_t *h, flow_t *f) {
    h->on_close(h->ctx, f->id);
    nw_connection_cancel(f->conn);
    for (int i = 0; i < f->npending; i++) dispatch_release(f->pending[i]);
    nw_release(f->conn);
    free(f);
}

static void close_flow(nwudp_t *h, uint64_t id) {
    pthread_mutex_lock(&h->lock);
    flow_t *f = take_flow(h, id);
    pthread_mutex_unlock(&h->lock);
    if (f) destroy_flow(h, f);
}

static void reap_flows(nwudp_t *h) {
    for (;;) {
        uint64_t now = monotonic_ns();
        uint64_t victim = 0;
        uint64_t oldest = UINT64_MAX;
        size_t unprotected = 0;
        pthread_mutex_lock(&h->lock);
        for (size_t i = 0; i < h->nflows; i++) {
            flow_t *f = h->flows[i];
            if (f->protected) continue;
            unprotected++;
            if (f->last_activity < oldest) {
                oldest = f->last_activity;
                victim = f->id;
            }
        }
        bool over_limit = unprotected > h->max_unprotected_flows;
        bool idle = victim != 0 && now - oldest >= NWUDP_UNPROTECTED_IDLE_NS;
        flow_t *f = (over_limit || idle) ? take_flow(h, victim) : NULL;
        pthread_mutex_unlock(&h->lock);
        if (!f) return;
        destroy_flow(h, f);
    }
}

static void recv_loop(nwudp_t *h, uint64_t id, nw_connection_t conn);

static void flow_ready(nwudp_t *h, uint64_t id) {
    pthread_mutex_lock(&h->lock);
    flow_t *f = find_flow(h, id);
    if (!f) {
        pthread_mutex_unlock(&h->lock);
        return;
    }
    nw_connection_t conn = f->conn;
    nw_retain(conn);
    f->ready = true;
    f->last_activity = monotonic_ns();
    int n = f->npending;
    dispatch_data_t pending[64];
    memcpy(pending, f->pending, sizeof(pending));
    f->npending = 0;
    pthread_mutex_unlock(&h->lock);
    nw_endpoint_t remote = nw_connection_copy_endpoint(conn);
    nw_path_t path = nw_connection_copy_current_path(conn);
    nw_endpoint_t local = path ? nw_path_copy_effective_local_endpoint(path) : NULL;
    const struct sockaddr *ra = remote ? nw_endpoint_get_address(remote) : NULL;
    const struct sockaddr *la = local ? nw_endpoint_get_address(local) : NULL;
    h->on_flow(h->ctx, id, ra, la);
    if (local) nw_release(local);
    if (path) nw_release(path);
    if (remote) nw_release(remote);
    for (int i = 0; i < n; i++) {
        nw_connection_send(conn, pending[i], NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                           ^(nw_error_t err) { (void)err; });
        dispatch_release(pending[i]);
    }
    recv_loop(h, id, conn);
    nw_release(conn);
}

static void start_flow(nwudp_t *h, flow_t *f) {
    uint64_t id = f->id;
    nw_connection_t conn = f->conn;
    nw_connection_set_queue(conn, h->queue);
    nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t err) {
        (void)err;
        if (state == nw_connection_state_ready) {
            flow_ready(h, id);
        } else if (state == nw_connection_state_failed ||
                   state == nw_connection_state_cancelled) {
            close_flow(h, id);
        }
    });
    nw_connection_start(conn);
}

static void recv_loop(nwudp_t *h, uint64_t id, nw_connection_t conn) {
    nw_retain(conn);
    nw_connection_receive_message(conn, ^(dispatch_data_t content, nw_content_context_t ctx,
                                          bool is_complete, nw_error_t err) {
        (void)ctx; (void)is_complete;
        if (content) {
            const void *ptr = NULL;
            size_t len = 0;
            dispatch_data_t map = dispatch_data_create_map(content, &ptr, &len);
            pthread_mutex_lock(&h->lock);
            flow_t *f = find_flow(h, id);
            if (f) f->last_activity = monotonic_ns();
            pthread_mutex_unlock(&h->lock);
            if (f && len > 0) h->on_recv(h->ctx, id, ptr, len);
            dispatch_release(map);
        }
        pthread_mutex_lock(&h->lock);
        bool active = find_flow(h, id) != NULL;
        pthread_mutex_unlock(&h->lock);
        if (err == NULL && active) recv_loop(h, id, conn);
        nw_release(conn);
    });
}

static flow_t *add_flow(nwudp_t *h, nw_connection_t conn) {
    flow_t *f = calloc(1, sizeof(*f));
    nw_retain(conn);
    f->conn = conn;
    f->last_activity = monotonic_ns();
    pthread_mutex_lock(&h->lock);
    f->id = ++h->next_id;
    if (h->nflows == h->cap) {
        h->cap = h->cap ? h->cap * 2 : 8;
        h->flows = realloc(h->flows, h->cap * sizeof(*h->flows));
    }
    h->flows[h->nflows++] = f;
    pthread_mutex_unlock(&h->lock);
    dispatch_async(h->queue, ^{ reap_flows(h); });
    return f;
}

nwudp_t *nwudp_create(void *ctx, nwudp_flow_cb on_flow, nwudp_recv_cb on_recv,
                      nwudp_close_cb on_close) {
    nwudp_t *h = calloc(1, sizeof(*h));
    h->ctx = ctx;
    h->on_flow = on_flow;
    h->on_recv = on_recv;
    h->on_close = on_close;
    h->max_unprotected_flows = NWUDP_MAX_UNPROTECTED_FLOWS;
    h->queue = dispatch_queue_create("hush.nwudp", DISPATCH_QUEUE_SERIAL);
    pthread_mutex_init(&h->lock, NULL);
    h->reaper = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, h->queue);
    dispatch_source_set_timer(h->reaper, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
                              NSEC_PER_SEC, NSEC_PER_MSEC * 100);
    dispatch_source_set_event_handler(h->reaper, ^{ reap_flows(h); });
    dispatch_resume(h->reaper);
    return h;
}

// Listen on `port`; `host` (may be NULL for all addresses) restricts the
// local address, e.g. "127.0.0.1".
int nwudp_listen(nwudp_t *h, const char *host, uint16_t port,
                 size_t max_unprotected_flows) {
    h->max_unprotected_flows = max_unprotected_flows;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", port);
    nw_parameters_t p = udp_params();
    if (host) {
        // The local endpoint carries the port; a listener created "with
        // port" refuses parameters that also name a local endpoint.
        nw_endpoint_t local = nw_endpoint_create_host(host, portstr);
        nw_parameters_set_local_endpoint(p, local);
        nw_release(local);
        h->listener = nw_listener_create(p);
    } else {
        h->listener = nw_listener_create_with_port(portstr, p);
    }
    nw_release(p);
    if (!h->listener) return -1;
    nw_listener_set_queue(h->listener, h->queue);
    nw_listener_set_new_connection_handler(h->listener, ^(nw_connection_t conn) {
        start_flow(h, add_flow(h, conn));
    });
    nw_listener_set_state_changed_handler(h->listener, ^(nw_listener_state_t state, nw_error_t err) {
        if (state == nw_listener_state_failed && err)
            fprintf(stderr, "nwudp: listener failed: %d\n", nw_error_get_error_code(err));
    });
    nw_listener_start(h->listener);
    return 0;
}

uint64_t nwudp_connect(nwudp_t *h, const char *host, uint16_t port) {
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", port);
    nw_endpoint_t ep = nw_endpoint_create_host(host, portstr);
    nw_parameters_t p = udp_params();
    nw_connection_t conn = nw_connection_create(ep, p);
    nw_release(p);
    nw_release(ep);
    flow_t *f = add_flow(h, conn);
    nw_release(conn);
    start_flow(h, f);
    return f->id;
}

// Send `count` datagrams of `seg` bytes each (the last may be shorter) from
// one buffer, as one batch.
int nwudp_send(nwudp_t *h, uint64_t id, const void *data, size_t len, size_t seg) {
    pthread_mutex_lock(&h->lock);
    flow_t *f = find_flow(h, id);
    if (!f) { pthread_mutex_unlock(&h->lock); return -1; }
    f->last_activity = monotonic_ns();
    if (!f->ready) {
        const char *p = data;
        while (len > 0 && f->npending < 64) {
            size_t n = len < seg ? len : seg;
            dispatch_data_t d = copy_datagram(h, p, n);
            if (!d) { pthread_mutex_unlock(&h->lock); return -1; }
            f->pending[f->npending++] = d;
            p += n; len -= n;
        }
        pthread_mutex_unlock(&h->lock);
        return 0;
    }
    nw_connection_t conn = f->conn;
    nw_retain(conn);
    pthread_mutex_unlock(&h->lock);
    const char *p = data;
    nw_connection_batch(conn, ^{
        const char *q = p; size_t left = len;
        while (left > 0) {
            size_t n = left < seg ? left : seg;
            dispatch_data_t d = copy_datagram(h, q, n);
            if (!d) break;
            nw_connection_send(conn, d, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                               ^(nw_error_t err) { (void)err; });
            dispatch_release(d);
            q += n; left -= n;
        }
    });
    nw_release(conn);
    return 0;
}

void nwudp_close_flow(nwudp_t *h, uint64_t id) {
    dispatch_async(h->queue, ^{ close_flow(h, id); });
}

int nwudp_protect_flow(nwudp_t *h, uint64_t id) {
    pthread_mutex_lock(&h->lock);
    flow_t *f = find_flow(h, id);
    if (f) f->protected = true;
    pthread_mutex_unlock(&h->lock);
    return f ? 0 : -1;
}
