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

#include "task.h"
#include "uv.h"

#include <fcntl.h>
#include <string.h>

#ifndef HAVE_KQUEUE
#    if defined(__APPLE__) || defined(__DragonFly__) || \
        defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#        define HAVE_KQUEUE 1
#    endif
#endif

static uv_fs_event_t fs_event;
static const char file_prefix[] = "fsevent-";
static const int fs_event_file_count = 16;
static uv_timer_t timer;
static int timer_cb_called;
static int close_cb_called;
static int fs_event_created;
static int fs_event_removed;
static int fs_event_cb_called;
static char fs_event_filename[PATH_MAX];
static int timer_cb_touch_called;
static int timer_cb_exact_called;

static void fs_event_fail(uv_fs_event_t* handle, const char* filename,
                          int events, int status)
{
    ASSERT(0 && "should never be called");
}

static void create_dir(const char* name)
{
    int r;
    uv_fs_t req;
    r = uv_fs_mkdir(NULL, &req, name, 0755, NULL);
    ASSERT(r == 0 || r == UV_EEXIST);
    uv_fs_req_cleanup(&req);
}

static void create_file(const char* name)
{
    int r;
    uv_file file;
    uv_fs_t req;

    r = uv_fs_open(NULL,
                   &req,
                   name,
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    file = r;
    uv_fs_req_cleanup(&req);
    r = uv_fs_close(NULL, &req, file, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&req);
}

static void touch_file(const char* name)
{
    int r;
    uv_file file;
    uv_fs_t req;
    uv_buf_t buf;

    r = uv_fs_open(NULL, &req, name, UV_FS_O_RDWR, 0, NULL);
    ASSERT_GE(r, 0);
    file = r;
    uv_fs_req_cleanup(&req);

    buf = uv_buf_init("foo", 4);
    r = uv_fs_write(NULL, &req, file, &buf, 1, -1, NULL);
    ASSERT_GE(r, 0);
    uv_fs_req_cleanup(&req);

    r = uv_fs_close(NULL, &req, file, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&req);
}

static void close_cb(uv_handle_t* handle)
{
    ASSERT_NOT_NULL(handle);
    close_cb_called++;
}

static void fail_cb(uv_fs_event_t* handle, const char* path, int events,
                    int status)
{
    ASSERT(0 && "fail_cb called");
}

static void fs_event_cb_dir(uv_fs_event_t* handle, const char* filename,
                            int events, int status)
{
    ++fs_event_cb_called;
    ASSERT_PTR_EQ(handle, &fs_event);
    ASSERT_OK(status);
    ASSERT_EQ(events, UV_CHANGE);
    ASSERT_OK(strcmp(filename, "file1"));
    ASSERT_OK(uv_fs_event_stop(handle));
    uv_close((uv_handle_t*)handle, close_cb);
}

static const char* fs_event_get_filename(int i)
{
    snprintf(fs_event_filename,
             sizeof(fs_event_filename),
             "watch_dir/%s%d",
             file_prefix,
             i);
    return fs_event_filename;
}

static void fs_event_create_files(uv_timer_t* handle)
{
    /* Make sure we're not attempting to create files we do not intend */
    ASSERT_LT(fs_event_created, fs_event_file_count);

    /* Create the file */
    create_file(fs_event_get_filename(fs_event_created));

    if (++fs_event_created < fs_event_file_count) {
        /* Create another file on a different event loop tick.  We do it this
         * way to avoid fs events coalescing into one fs event. */
        ASSERT_OK(uv_timer_start(&timer, fs_event_create_files, 100, 0));
    }
}

static void fs_event_unlink_files(uv_timer_t* handle)
{
    int r;
    int i;

    /* NOTE: handle might be NULL if invoked not as timer callback */
    if (handle == NULL) {
        /* Unlink all files */
        for (i = 0; i < 16; i++) {
            r = remove(fs_event_get_filename(i));
            if (handle != NULL)
                ASSERT_OK(r);
        }
    } else {
        /* Make sure we're not attempting to remove files we do not intend */
        ASSERT_LT(fs_event_removed, fs_event_file_count);

        /* Remove the file */
        ASSERT_OK(remove(fs_event_get_filename(fs_event_removed)));

        if (++fs_event_removed < fs_event_file_count) {
            /* Remove another file on a different event loop tick.  We do it
             * this way to avoid fs events coalescing into one fs event. */
            ASSERT_OK(uv_timer_start(&timer, fs_event_unlink_files, 1, 0));
        }
    }
}

static void fs_event_cb_dir_multi_file(uv_fs_event_t* handle,
                                       const char* filename, int events,
                                       int status)
{
    fs_event_cb_called++;
    ASSERT_PTR_EQ(handle, &fs_event);
    ASSERT_OK(status);
    ASSERT(events == UV_CHANGE || events == UV_RENAME);
    ASSERT_NOT_NULL(filename);
    ASSERT_MEM_EQ(filename, file_prefix, sizeof(file_prefix) - 1);

    if (fs_event_created + fs_event_removed == fs_event_file_count) {
        /* Once we've processed all create events, delete all files */
        ASSERT_OK(uv_timer_start(&timer, fs_event_unlink_files, 1, 0));
    } else if (fs_event_cb_called == 2 * fs_event_file_count) {
        /* Once we've processed all create and delete events, stop watching */
        uv_close((uv_handle_t*)&timer, close_cb);
        uv_close((uv_handle_t*)handle, close_cb);
    }
}

static void fs_event_cb_file(uv_fs_event_t* handle, const char* filename,
                             int events, int status)
{
    ++fs_event_cb_called;
    ASSERT_PTR_EQ(handle, &fs_event);
    ASSERT_OK(status);
    ASSERT_EQ(events, UV_CHANGE);
    ASSERT_OK(strcmp(filename, "file2"));
    ASSERT_OK(uv_fs_event_stop(handle));
    uv_close((uv_handle_t*)handle, close_cb);
}

static void fs_event_cb_file_current_dir(uv_fs_event_t* handle,
                                         const char* filename, int events,
                                         int status)
{
    ++fs_event_cb_called;

    ASSERT_PTR_EQ(handle, &fs_event);
    ASSERT_OK(status);
    ASSERT_EQ(events, UV_CHANGE);
    ASSERT_OK(strcmp(filename, "watch_file"));

    uv_close((uv_handle_t*)handle, close_cb);
}

static void timer_cb_file(uv_timer_t* handle)
{
    ++timer_cb_called;

    if (timer_cb_called == 1) {
        touch_file("watch_dir/file1");
    } else {
        touch_file("watch_dir/file2");
        uv_close((uv_handle_t*)handle, close_cb);
    }
}

static void timer_cb_touch(uv_timer_t* timer)
{
    uv_close((uv_handle_t*)timer, NULL);
    touch_file((char*)timer->data);
    timer_cb_touch_called++;
}

static void timer_cb_exact(uv_timer_t* handle)
{
    int r;

    if (timer_cb_exact_called == 0) {
        touch_file("watch_dir/file.js");
    } else {
        uv_close((uv_handle_t*)handle, NULL);
        r = uv_fs_event_stop(&fs_event);
        ASSERT_OK(r);
        uv_close((uv_handle_t*)&fs_event, NULL);
    }

    ++timer_cb_exact_called;
}

static void timer_cb_watch_twice(uv_timer_t* handle)
{
    uv_fs_event_t* handles = handle->data;
    uv_close((uv_handle_t*)(handles + 0), NULL);
    uv_close((uv_handle_t*)(handles + 1), NULL);
    uv_close((uv_handle_t*)handle, NULL);
}

static void fs_event_cb_close(uv_fs_event_t* handle, const char* filename,
                              int events, int status)
{
    ASSERT_OK(status);

    ASSERT_LT(fs_event_cb_called, 3);
    ++fs_event_cb_called;

    if (fs_event_cb_called == 3) {
        uv_close((uv_handle_t*)handle, close_cb);
    }
}


TEST_IMPL(fs_event_watch_dir)
{
    uv_loop_t* loop = uv_default_loop();
    int r;

    /* Setup */
    fs_event_unlink_files(NULL);
    remove("watch_dir/file2");
    remove("watch_dir/file1");
    remove("watch_dir/");
    create_dir("watch_dir");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(
        &fs_event, fs_event_cb_dir_multi_file, "watch_dir", 0);
    ASSERT_OK(r);
    r = uv_timer_init(loop, &timer);
    ASSERT_OK(r);
    r = uv_timer_start(&timer, fs_event_create_files, 100, 0);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(fs_event_cb_called, fs_event_created + fs_event_removed);
    ASSERT_EQ(2, close_cb_called);

    /* Cleanup */
    fs_event_unlink_files(NULL);
    remove("watch_dir/file2");
    remove("watch_dir/file1");
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_event_watch_dir_recursive)
{
    RETURN_SKIP("Recursive directory watching not supported on this platform.");
}

TEST_IMPL(fs_event_watch_file)
{
    uv_loop_t* loop = uv_default_loop();
    int r;

    /* Setup */
    remove("watch_dir/file2");
    remove("watch_dir/file1");
    remove("watch_dir/");
    create_dir("watch_dir");
    create_file("watch_dir/file1");
    create_file("watch_dir/file2");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_cb_file, "watch_dir/file2", 0);
    ASSERT_OK(r);
    r = uv_timer_init(loop, &timer);
    ASSERT_OK(r);
    r = uv_timer_start(&timer, timer_cb_file, 100, 100);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(1, fs_event_cb_called);
    ASSERT_EQ(2, timer_cb_called);
    ASSERT_EQ(2, close_cb_called);

    /* Cleanup */
    remove("watch_dir/file2");
    remove("watch_dir/file1");
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_watch_file_exact_path)
{
    /*
      This test watches a file named "file.jsx" and modifies a file named
      "file.js". The test verifies that no events occur for file.jsx.
    */

    uv_loop_t* loop;
    int r;

    loop = uv_default_loop();

    /* Setup */
    remove("watch_dir/file.js");
    remove("watch_dir/file.jsx");
    remove("watch_dir/");
    create_dir("watch_dir");
    create_file("watch_dir/file.js");
    create_file("watch_dir/file.jsx");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_fail, "watch_dir/file.jsx", 0);
    ASSERT_OK(r);
    r = uv_timer_init(loop, &timer);
    ASSERT_OK(r);
    r = uv_timer_start(&timer, timer_cb_exact, 100, 100);
    ASSERT_OK(r);
    r = uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_OK(r);
    ASSERT_EQ(2, timer_cb_exact_called);

    /* Cleanup */
    remove("watch_dir/file.js");
    remove("watch_dir/file.jsx");
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_watch_file_twice)
{
    const char path[] = "test/fixtures/empty_file";
    uv_fs_event_t watchers[2];
    uv_timer_t timer;
    uv_loop_t* loop;

    loop = uv_default_loop();
    timer.data = watchers;

    ASSERT_OK(uv_fs_event_init(loop, watchers + 0));
    ASSERT_OK(uv_fs_event_start(watchers + 0, fail_cb, path, 0));
    ASSERT_OK(uv_fs_event_init(loop, watchers + 1));
    ASSERT_OK(uv_fs_event_start(watchers + 1, fail_cb, path, 0));
    ASSERT_OK(uv_timer_init(loop, &timer));
    ASSERT_OK(uv_timer_start(&timer, timer_cb_watch_twice, 10, 0));
    ASSERT_OK(uv_run(loop, UV_RUN_DEFAULT));

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_watch_file_current_dir)
{
    uv_timer_t timer;
    uv_loop_t* loop;
    int r;

    loop = uv_default_loop();

    /* Setup */
    remove("watch_file");
    create_file("watch_file");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(
        &fs_event, fs_event_cb_file_current_dir, "watch_file", 0);
    ASSERT_OK(r);


    r = uv_timer_init(loop, &timer);
    ASSERT_OK(r);

    timer.data = "watch_file";
    r = uv_timer_start(&timer, timer_cb_touch, 1100, 0);
    ASSERT_OK(r);

    ASSERT_OK(timer_cb_touch_called);
    ASSERT_OK(fs_event_cb_called);
    ASSERT_OK(close_cb_called);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(1, timer_cb_touch_called);
    /* FSEvents on macOS sometimes sends one change event, sometimes two. */
    ASSERT_NE(0, fs_event_cb_called);
    ASSERT_EQ(1, close_cb_called);

    /* Cleanup */
    remove("watch_file");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_no_callback_after_close)
{
    uv_loop_t* loop = uv_default_loop();
    int r;

    /* Setup */
    remove("watch_dir/file1");
    remove("watch_dir/");
    create_dir("watch_dir");
    create_file("watch_dir/file1");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_cb_file, "watch_dir/file1", 0);
    ASSERT_OK(r);


    uv_close((uv_handle_t*)&fs_event, close_cb);
    touch_file("watch_dir/file1");
    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_OK(fs_event_cb_called);
    ASSERT_EQ(1, close_cb_called);

    /* Cleanup */
    remove("watch_dir/file1");
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_no_callback_on_close)
{
    uv_loop_t* loop = uv_default_loop();
    int r;

    /* Setup */
    remove("watch_dir/file1");
    remove("watch_dir/");
    create_dir("watch_dir");
    create_file("watch_dir/file1");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_cb_file, "watch_dir/file1", 0);
    ASSERT_OK(r);

    uv_close((uv_handle_t*)&fs_event, close_cb);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_OK(fs_event_cb_called);
    ASSERT_EQ(1, close_cb_called);

    /* Cleanup */
    remove("watch_dir/file1");
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


static void timer_cb(uv_timer_t* handle)
{
    int r;

    r = uv_fs_event_init(handle->loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_fail, ".", 0);
    ASSERT_OK(r);

    uv_close((uv_handle_t*)&fs_event, close_cb);
    uv_close((uv_handle_t*)handle, close_cb);
}


TEST_IMPL(fs_event_immediate_close)
{
    uv_timer_t timer;
    uv_loop_t* loop;
    int r;

    loop = uv_default_loop();

    r = uv_timer_init(loop, &timer);
    ASSERT_OK(r);

    r = uv_timer_start(&timer, timer_cb, 1, 0);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(2, close_cb_called);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_event_close_with_pending_event)
{
    uv_loop_t* loop;
    int r;

    loop = uv_default_loop();

    create_dir("watch_dir");
    create_file("watch_dir/file");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_fail, "watch_dir", 0);
    ASSERT_OK(r);

    /* Generate an fs event. */
    touch_file("watch_dir/file");

    uv_close((uv_handle_t*)&fs_event, close_cb);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(1, close_cb_called);

    /* Clean up */
    remove("watch_dir/file");
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_close_with_pending_delete_event)
{
    uv_loop_t* loop;
    int r;

    loop = uv_default_loop();

    create_dir("watch_dir");
    create_file("watch_dir/file");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_fail, "watch_dir/file", 0);
    ASSERT_OK(r);

    /* Generate an fs event. */
    remove("watch_dir/file");

    /* Allow time for the remove event to propagate to the pending list. */
    /* XXX - perhaps just for __sun? */
    uv_sleep(1100);
    uv_update_time(loop);

    uv_close((uv_handle_t*)&fs_event, close_cb);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(1, close_cb_called);

    /* Clean up */
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_close_in_callback)
{
    uv_loop_t* loop;
    int r;

    loop = uv_default_loop();

    fs_event_unlink_files(NULL);
    create_dir("watch_dir");

    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_cb_close, "watch_dir", 0);
    ASSERT_OK(r);

    r = uv_timer_init(loop, &timer);
    ASSERT_OK(r);
    r = uv_timer_start(&timer, fs_event_create_files, 100, 0);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)&timer, close_cb);

    uv_run(loop, UV_RUN_ONCE);

    ASSERT_EQ(2, close_cb_called);
    ASSERT_EQ(3, fs_event_cb_called);

    /* Clean up */
    fs_event_unlink_files(NULL);
    remove("watch_dir/");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_start_and_close)
{
    uv_loop_t* loop;
    uv_fs_event_t fs_event1;
    uv_fs_event_t fs_event2;
    int r;

    loop = uv_default_loop();

    create_dir("watch_dir");

    r = uv_fs_event_init(loop, &fs_event1);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event1, fs_event_cb_dir, "watch_dir", 0);
    ASSERT_OK(r);

    r = uv_fs_event_init(loop, &fs_event2);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event2, fs_event_cb_dir, "watch_dir", 0);
    ASSERT_OK(r);

    uv_close((uv_handle_t*)&fs_event2, close_cb);
    uv_close((uv_handle_t*)&fs_event1, close_cb);

    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(2, close_cb_called);

    remove("watch_dir/");
    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_getpath)
{
    uv_loop_t* loop = uv_default_loop();
    unsigned i;
    int r;
    char buf[1024];
    size_t len;
    const char* const watch_dir[] = {
        "watch_dir",
        "watch_dir/",
        "watch_dir///",
        "watch_dir/subfolder/..",
        "watch_dir//subfolder//..//",
    };

    create_dir("watch_dir");
    create_dir("watch_dir/subfolder");


    for (i = 0; i < ARRAY_SIZE(watch_dir); i++) {
        r = uv_fs_event_init(loop, &fs_event);
        ASSERT_OK(r);
        len = sizeof buf;
        r = uv_fs_event_getpath(&fs_event, buf, &len);
        ASSERT_EQ(r, UV_EINVAL);
        r = uv_fs_event_start(&fs_event, fail_cb, watch_dir[i], 0);
        ASSERT_OK(r);
        len = 0;
        r = uv_fs_event_getpath(&fs_event, buf, &len);
        ASSERT_EQ(r, UV_ENOBUFS);
        ASSERT_LT(len, sizeof buf); /* sanity check */
        ASSERT_EQ(len, strlen(watch_dir[i]) + 1);
        r = uv_fs_event_getpath(&fs_event, buf, &len);
        ASSERT_OK(r);
        ASSERT_EQ(len, strlen(watch_dir[i]));
        ASSERT(strcmp(buf, watch_dir[i]) == 0);
        r = uv_fs_event_stop(&fs_event);
        ASSERT_OK(r);
        uv_close((uv_handle_t*)&fs_event, close_cb);

        uv_run(loop, UV_RUN_DEFAULT);

        ASSERT_EQ(1, close_cb_called);
        close_cb_called = 0;
    }

    remove("watch_dir/");
    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_event_error_reporting)
{
    /* No-op, needed only for FSEvents backend */

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}

TEST_IMPL(fs_event_watch_invalid_path)
{
    uv_loop_t* loop;
    int r;

    loop = uv_default_loop();
    r = uv_fs_event_init(loop, &fs_event);
    ASSERT_OK(r);
    r = uv_fs_event_start(&fs_event, fs_event_cb_file, "<:;", 0);
    ASSERT(r);
    ASSERT_OK(uv_is_active((uv_handle_t*)&fs_event));
    r = uv_fs_event_start(&fs_event, fs_event_cb_file, "", 0);
    ASSERT(r);
    ASSERT_OK(uv_is_active((uv_handle_t*)&fs_event));
    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

static int fs_event_cb_stop_calls;

static void fs_event_cb_stop(uv_fs_event_t* handle, const char* path,
                             int events, int status)
{
    uv_fs_event_stop(handle);
    fs_event_cb_stop_calls++;
}

TEST_IMPL(fs_event_stop_in_cb)
{
    uv_fs_event_t fs;
    uv_timer_t timer;
    char path[] = "fs_event_stop_in_cb.txt";

    remove(path);
    create_file(path);

    ASSERT_OK(uv_fs_event_init(uv_default_loop(), &fs));
    ASSERT_OK(uv_fs_event_start(&fs, fs_event_cb_stop, path, 0));

    /* Note: timer_cb_touch() closes the handle. */
    timer.data = path;
    ASSERT_OK(uv_timer_init(uv_default_loop(), &timer));
    ASSERT_OK(uv_timer_start(&timer, timer_cb_touch, 100, 0));

    ASSERT_OK(fs_event_cb_stop_calls);
    ASSERT_OK(timer_cb_touch_called);

    ASSERT_OK(uv_run(uv_default_loop(), UV_RUN_DEFAULT));

    ASSERT_EQ(1, fs_event_cb_stop_calls);
    ASSERT_EQ(1, timer_cb_touch_called);

    uv_close((uv_handle_t*)&fs, NULL);
    ASSERT_OK(uv_run(uv_default_loop(), UV_RUN_DEFAULT));
    ASSERT_EQ(1, fs_event_cb_stop_calls);

    remove(path);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}
