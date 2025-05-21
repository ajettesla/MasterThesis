#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdint.h>

// Convert a timespec structure to nanoseconds for easier math
static inline int64_t timespec_to_ns(struct timespec *ts) {
    return ts->tv_sec * 1000000000LL + ts->tv_nsec;
}

int main() {
    struct timespec ts_realtime, ts_monoraw;

    // CLOCK_REALTIME gives the current wall-clock time (UTC)
    // This clock is synchronized using NTP/PTP services with external accurate time sources (like GPS or atomic clocks)
    // It's the most accurate when you want to know the real current time
    clock_gettime(CLOCK_REALTIME, &ts_realtime);

    // CLOCK_MONOTONIC_RAW gives raw hardware clock time since boot
    // This clock is not adjusted by the system (e.g., no NTP/PTP correction)
    // It's great for measuring precise durations (because it won't jump or drift)
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts_monoraw);

    // Convert both times to nanoseconds
    int64_t realtime_ns = timespec_to_ns(&ts_realtime);
    int64_t monoraw_ns = timespec_to_ns(&ts_monoraw);

    // Display both clock values
    printf("CLOCK_REALTIME (UTC):        %ld ns\n", realtime_ns);
    printf("CLOCK_MONOTONIC_RAW (since boot): %ld ns\n", monoraw_ns);

    // Calculate and display the offset between them
    int64_t offset = realtime_ns - monoraw_ns;
    printf("Offset between clocks:       %ld ns\n", offset);

    return 0;
}

#here we are using CLOCK_REALTIME in the main connectionTracking Program.
