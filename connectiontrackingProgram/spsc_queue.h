#ifndef SPSC_QUEUE_H
#define SPSC_QUEUE_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SPSC_QUEUE_CAPACITY 5120  // for ~5MB if each string is 1024 bytes

typedef struct {
    char **buffer;
    size_t capacity;
    atomic_size_t head;
    atomic_size_t tail;
} spsc_queue_t;

// Allocate the queue
static inline void spsc_queue_init(spsc_queue_t *q, size_t capacity) {
    q->buffer = calloc(capacity, sizeof(char*));
    q->capacity = capacity;
    atomic_init(&q->head, 0);
    atomic_init(&q->tail, 0);
}

// Free all memory in the queue
static inline void spsc_queue_destroy(spsc_queue_t *q) {
    for (size_t i = 0; i < q->capacity; ++i) {
        if (q->buffer[i]) free(q->buffer[i]);
    }
    free(q->buffer);
}

// Try to enqueue (returns 1 on success, 0 on full)
static inline int spsc_queue_enqueue(spsc_queue_t *q, const char *data) {
    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t next_tail = (tail + 1) % q->capacity;
    size_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    if (next_tail == head) return 0; // full
    if (q->buffer[tail]) free(q->buffer[tail]);
    q->buffer[tail] = strdup(data);
    atomic_store_explicit(&q->tail, next_tail, memory_order_release);
    return 1;
}

// Try to dequeue (returns 1 on success, 0 on empty)
static inline int spsc_queue_dequeue(spsc_queue_t *q, char **out) {
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (head == tail) return 0; // empty
    *out = q->buffer[head];
    q->buffer[head] = NULL;
    atomic_store_explicit(&q->head, (head + 1) % q->capacity, memory_order_release);
    return 1;
}

// Check if full
static inline int spsc_queue_full(spsc_queue_t *q) {
    size_t tail = atomic_load(&q->tail);
    size_t next_tail = (tail + 1) % q->capacity;
    size_t head = atomic_load(&q->head);
    return (next_tail == head);
}

// Check if empty
static inline int spsc_queue_empty(spsc_queue_t *q) {
    size_t head = atomic_load(&q->head);
    size_t tail = atomic_load(&q->tail);
    return (head == tail);
}

#endif // SPSC_QUEUE_H

