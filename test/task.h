/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef TASK_H_
#define TASK_H_

#include "uv.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/resource.h> /* setrlimit() */
#include <sys/time.h>

#ifdef __clang__
#    pragma clang diagnostic ignored "-Wvariadic-macros"
#    pragma clang diagnostic ignored "-Wc99-extensions"
#endif

#ifdef __GNUC__
#    pragma GCC diagnostic ignored "-Wvariadic-macros"
#endif

#define TEST_PORT 9123
#define TEST_PORT_2 9124
#define TEST_PORT_3 9125

#define TEST_PIPENAME "/tmp/uv-test-sock"
#define TEST_PIPENAME_2 "/tmp/uv-test-sock2"
#define TEST_PIPENAME_3 "/tmp/uv-test-sock3"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define container_of(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

typedef enum
{
    TCP = 0,
    UDP,
    PIPE
} stream_type;

/* Die with fatal error. */
#define FATAL(msg)                                    \
    do {                                              \
        fprintf(stderr,                               \
                "Fatal error in %s on line %d: %s\n", \
                __FILE__,                             \
                __LINE__,                             \
                msg);                                 \
        fflush(stderr);                               \
        abort();                                      \
    } while (0)

/* Have our own assert, so we are sure it does not get optimized away in
 * a release build.
 */
#define ASSERT(expr)                                           \
    do {                                                       \
        if (!(expr)) {                                         \
            fprintf(stderr,                                    \
                    "Assertion failed in %s on line %d: %s\n", \
                    __FILE__,                                  \
                    __LINE__,                                  \
                    #expr);                                    \
            abort();                                           \
        }                                                      \
    } while (0)

#define ASSERT_BASE(a, operator, b, type, conv)                      \
    do {                                                             \
        volatile type eval_a = (type)(a);                            \
        volatile type eval_b = (type)(b);                            \
        if (!(eval_a operator eval_b)) {                             \
            fprintf(stderr,                                          \
                    "Assertion failed in %s on line %d: `%s %s %s` " \
                    "(%" conv " %s %" conv ")\n",                    \
                    __FILE__,                                        \
                    __LINE__,                                        \
                    #a,                                              \
                    #operator,                                       \
                    #b,                                              \
                    eval_a,                                          \
                    #operator,                                       \
                    eval_b);                                         \
            abort();                                                 \
        }                                                            \
    } while (0)

#define ASSERT_BASE_STR(expr, a, operator, b, type, conv)                \
    do {                                                                 \
        if (!(expr)) {                                                   \
            fprintf(stderr,                                            \
            "Assertion failed in %s on line %d: `%s %s %s` "   \
            "(%" conv " %s %" conv ")\n",                          \
            __FILE__,                                          \
            __LINE__,                                          \
            #a,                                                \
            #operator,                                         \
            #b,                                                \
            (type)a,                                           \
            #operator,                                         \
            (type)b); \
            abort();                                                     \
        }                                                                \
    } while (0)

#define ASSERT_BASE_LEN(expr, a, operator, b, conv, len)               \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr,                                          \
            "Assertion failed in %s on line %d: `%s %s %s` " \
            "(%.*"#conv" %s %.*"#conv")\n",                  \
            __FILE__,                                        \
            __LINE__,                                        \
            #a,                                              \
            #operator,                                       \
            #b,                                              \
            (int)len,                                        \
            a,                                               \
            #operator,                                       \
            (int)len,                                        \
            b); \
            abort();                                                   \
        }                                                              \
    } while (0)

#define ASSERT_BASE_HEX(expr, a, operator, b, size)                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            int i;                                                     \
            unsigned char* a_ = (unsigned char*)a;                     \
            unsigned char* b_ = (unsigned char*)b;                     \
            fprintf(stderr,                                            \
                    "Assertion failed in %s on line %d: `%s %s %s` (", \
                    __FILE__,                                          \
                    __LINE__,                                          \
                    #a,                                                \
                    #operator,                                         \
                    #b);                                               \
            for (i = 0; i < size; ++i) {                               \
                if (i > 0)                                             \
                    fprintf(stderr, ":");                              \
                fprintf(stderr, "%02X", a_[i]);                        \
            }                                                          \
            fprintf(stderr, " %s ", #operator);                        \
            for (i = 0; i < size; ++i) {                               \
                if (i > 0)                                             \
                    fprintf(stderr, ":");                              \
                fprintf(stderr, "%02X", b_[i]);                        \
            }                                                          \
            fprintf(stderr, ")\n");                                    \
            abort();                                                   \
        }                                                              \
    } while (0)

#define ASSERT_EQ(a, b) ASSERT_BASE(a, ==, b, int64_t, PRId64)
#define ASSERT_GE(a, b) ASSERT_BASE(a, >=, b, int64_t, PRId64)
#define ASSERT_GT(a, b) ASSERT_BASE(a, >, b, int64_t, PRId64)
#define ASSERT_LE(a, b) ASSERT_BASE(a, <=, b, int64_t, PRId64)
#define ASSERT_LT(a, b) ASSERT_BASE(a, <, b, int64_t, PRId64)
#define ASSERT_NE(a, b) ASSERT_BASE(a, !=, b, int64_t, PRId64)
#define ASSERT_OK(a) ASSERT_BASE(a, ==, 0, int64_t, PRId64)

#define ASSERT_UINT64_EQ(a, b) ASSERT_BASE(a, ==, b, uint64_t, PRIu64)
#define ASSERT_UINT64_GE(a, b) ASSERT_BASE(a, >=, b, uint64_t, PRIu64)
#define ASSERT_UINT64_GT(a, b) ASSERT_BASE(a, >, b, uint64_t, PRIu64)
#define ASSERT_UINT64_LE(a, b) ASSERT_BASE(a, <=, b, uint64_t, PRIu64)
#define ASSERT_UINT64_LT(a, b) ASSERT_BASE(a, <, b, uint64_t, PRIu64)
#define ASSERT_UINT64_NE(a, b) ASSERT_BASE(a, !=, b, uint64_t, PRIu64)

#define ASSERT_DOUBLE_EQ(a, b) ASSERT_BASE(a, ==, b, double, "f")
#define ASSERT_DOUBLE_GE(a, b) ASSERT_BASE(a, >=, b, double, "f")
#define ASSERT_DOUBLE_GT(a, b) ASSERT_BASE(a, >, b, double, "f")
#define ASSERT_DOUBLE_LE(a, b) ASSERT_BASE(a, <=, b, double, "f")
#define ASSERT_DOUBLE_LT(a, b) ASSERT_BASE(a, <, b, double, "f")
#define ASSERT_DOUBLE_NE(a, b) ASSERT_BASE(a, !=, b, double, "f")

#define ASSERT_STR_EQ(a, b) \
    ASSERT_BASE_STR(strcmp(a, b) == 0, a, ==, b, char*, "s")

#define ASSERT_STR_NE(a, b) \
    ASSERT_BASE_STR(strcmp(a, b) != 0, a, !=, b, char*, "s")

#define ASSERT_MEM_EQ(a, b, size) \
    ASSERT_BASE_LEN(memcmp(a, b, size) == 0, a, ==, b, s, size)

#define ASSERT_MEM_NE(a, b, size) \
    ASSERT_BASE_LEN(memcmp(a, b, size) != 0, a, !=, b, s, size)

#define ASSERT_MEM_HEX_EQ(a, b, size) \
    ASSERT_BASE_HEX(memcmp(a, b, size) == 0, a, ==, b, size)

#define ASSERT_MEM_HEX_NE(a, b, size) \
    ASSERT_BASE_HEX(memcmp(a, b, size) != 0, a, !=, b, size)

#define ASSERT_NULL(a) ASSERT_BASE(a, ==, NULL, void*, "p")

#define ASSERT_NOT_NULL(a) ASSERT_BASE(a, !=, NULL, void*, "p")

#define ASSERT_PTR_EQ(a, b) ASSERT_BASE(a, ==, b, void*, "p")

#define ASSERT_PTR_NE(a, b) ASSERT_BASE(a, !=, b, void*, "p")

#define ASSERT_PTR_LT(a, b) ASSERT_BASE(a, <, b, void*, "p")

/* This macro cleans up the event loop. This is used to avoid valgrind
 * warnings about memory being "leaked" by the event loop.
 */
#define MAKE_VALGRIND_HAPPY(loop)          \
    do {                                   \
        close_loop(loop);                  \
        ASSERT_EQ(0, uv_loop_close(loop)); \
        uv_library_shutdown();             \
    } while (0)

/* Just sugar for wrapping the main() for a task or helper. */
#define TEST_IMPL(name)        \
    int run_test_##name(void); \
    int run_test_##name(void)

#define BENCHMARK_IMPL(name)        \
    int run_benchmark_##name(void); \
    int run_benchmark_##name(void)

#define HELPER_IMPL(name)        \
    int run_helper_##name(void); \
    int run_helper_##name(void)

/* Format big numbers nicely. */
char* fmt(char (*buf)[32], double d);

/* Reserved test exit codes. */
enum test_status
{
    TEST_OK = 0,
    TEST_SKIP = 7
};

#define RETURN_OK()     \
    do {                \
        return TEST_OK; \
    } while (0)

#define RETURN_SKIP(explanation)              \
    do {                                      \
        fprintf(stderr, "%s\n", explanation); \
        fflush(stderr);                       \
        return TEST_SKIP;                     \
    } while (0)

#define TEST_FILE_LIMIT(num)                               \
    do {                                                   \
        struct rlimit lim;                                 \
        lim.rlim_cur = (num);                              \
        lim.rlim_max = lim.rlim_cur;                       \
        if (setrlimit(RLIMIT_NOFILE, &lim))                \
            RETURN_SKIP("File descriptor limit too low."); \
    } while (0)

#if defined(__clang__) || defined(__GNUC__) || defined(__INTEL_COMPILER)
#    define UNUSED __attribute__((unused))
#else
#    define UNUSED
#endif

extern void notify_parent_process(void);

/* Fully close a loop */
static void close_walk_cb(uv_handle_t* handle, void* arg)
{
    if (!uv_is_closing(handle))
        uv_close(handle, NULL);
}

UNUSED static void close_loop(uv_loop_t* loop)
{
    uv_walk(loop, close_walk_cb, NULL);
    uv_run(loop, UV_RUN_DEFAULT);
}

UNUSED static int can_ipv6(void)
{
    uv_interface_address_t* addr;
    int supported;
    int count;
    int i;

    if (uv_interface_addresses(&addr, &count))
        return 0; /* Assume no IPv6 support on failure. */

    supported = 0;
    for (i = 0; supported == 0 && i < count; i += 1)
        supported = (AF_INET6 == addr[i].address.address6.sin6_family);

    uv_free_interface_addresses(addr, count);
    return supported;
}

#endif /* TASK_H_ */
