/* SPDX-License-Identifier: MIT */
#ifndef COVBRIDGE_H
#define COVBRIDGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef CB_MAX_EDGES
#define CB_MAX_EDGES 524288u
#endif
#define CB_MAX_INPUT (1024u * 1024u)
#define CB_COUNTS64 1u
#define CB_INLINE8  2u

/* Zero-initialize snapshots. counts[i] belongs to instrumentation slot i.
   capacity is managed by the library. Do not copy owning structs by value. */
typedef struct cb_snapshot {
    uint64_t run_id, layout_id;
    uint32_t mode, nslots;
    uint64_t *counts;
    uint32_t capacity;
} cb_snapshot;

/* Choose ONE collector at link time: guard (shared) or inline8 (local).
   init: after instrumentation constructors, before workers/forks.
   begin/end: ONE controller; all producers must be parked at BOTH boundaries.
   A nonzero layout_id must identify the exact build AND registration order.
   Run IDs must be nonzero and strictly increasing in a collector session.
   All fallible functions return 0 on success, -1 with errno on failure. */
int cb_init(uint64_t layout_id);
uint32_t cb_slots(void);
void cb_producer_enable(void);
int cb_begin(uint64_t run_id);
int cb_end(cb_snapshot *out);

int cb_snapshot_reserve(cb_snapshot *s, uint32_t nslots);
void cb_snapshot_free(cb_snapshot *s);
/* Sum disjoint contributions from the SAME build/run. Do not merge the same
   cumulative snapshot twice. Metadata must agree. No partial sum on overflow. */
int cb_snapshot_merge(cb_snapshot *dst, const cb_snapshot *src);

/* Framed, bounded, big-endian protocol over an ALREADY CONNECTED stream socket.
   timeout_ms is a total deadline per call. Close the connection after any error.
   These calls do not authenticate the peer. One reader and one writer per fd.
   recv_snapshot requires the expected run and exact target layout IDs. */
int cb_send_snapshot(int fd, const cb_snapshot *s, int timeout_ms);
int cb_recv_snapshot(int fd, uint64_t run_id, uint64_t layout_id,
                     cb_snapshot *out, int timeout_ms);

/* Optional workload transport used by the demos. You may use your application's
   existing input transport instead. recv_input uses caller-owned storage. */
int cb_send_input(int fd, uint64_t run_id, const uint8_t *data, uint32_t size,
                  int timeout_ms);
int cb_recv_input(int fd, uint64_t *run_id, uint8_t *data, uint32_t capacity,
                  uint32_t *size, int timeout_ms);

/* Link only in the libFuzzer process. Clear once per test, then import each
   disjoint worker contribution before LLVMFuzzerTestOneInput returns.
   Different builds need distinct, fixed offset ranges; validate their identities.
   Counts are summed with saturation at 255, NEVER reduced modulo 256. */
void cb_libfuzzer_clear(void);
int cb_libfuzzer_import(const cb_snapshot *s, uint32_t offset);
#ifdef __cplusplus
}
#endif
#endif
