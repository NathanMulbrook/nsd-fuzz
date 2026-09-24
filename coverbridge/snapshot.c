/* SPDX-License-Identifier: MIT */
#include "covbridge.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int cb_snapshot_reserve(cb_snapshot *s, uint32_t n) {
    if (!s || !n || n > CB_MAX_EDGES) { errno = EINVAL; return -1; }
    if (s->capacity < n) {
        uint64_t *p = realloc(s->counts, (size_t)n * sizeof(*p));
        if (!p) return -1;
        s->counts = p;
        s->capacity = n;
    }
    s->nslots = n;
    return 0;
}
void cb_snapshot_free(cb_snapshot *s) {
    if (s) { free(s->counts); memset(s, 0, sizeof(*s)); }
}
int cb_snapshot_merge(cb_snapshot *d, const cb_snapshot *s) {
    if (!d || !s || !d->counts || !s->counts || !s->nslots ||
        s->nslots > CB_MAX_EDGES || d->nslots != s->nslots ||
        d->layout_id != s->layout_id || d->run_id != s->run_id ||
        d->mode != s->mode || s->mode != CB_COUNTS64) {
        /* Merging modulo-256 counters as exact counts is deliberately rejected. */
        errno = EINVAL; return -1;
    }
    for (uint32_t i = 0; i < s->nslots; ++i)
        if (UINT64_MAX - d->counts[i] < s->counts[i]) {
            errno = EOVERFLOW; return -1;
        }
    for (uint32_t i = 0; i < s->nslots; ++i) d->counts[i] += s->counts[i];
    return 0;
}
