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

#include <errno.h>
#include <fcntl.h>
#include <limits.h> /* INT_MAX, PATH_MAX, IOV_MAX */
#include <string.h> /* memset */
#include <sys/stat.h>

#include <unistd.h> /* unlink, rmdir, etc. */

#define TOO_LONG_NAME_LENGTH 65536
#define PATHMAX 4096

typedef struct
{
    const char* path;
    double atime;
    double mtime;
} utime_check_t;


static int dummy_cb_count;
static int close_cb_count;
static int create_cb_count;
static int open_cb_count;
static int read_cb_count;
static int write_cb_count;
static int unlink_cb_count;
static int mkdir_cb_count;
static int mkdtemp_cb_count;
static int mkstemp_cb_count;
static int rmdir_cb_count;
static int scandir_cb_count;
static int stat_cb_count;
static int rename_cb_count;
static int fsync_cb_count;
static int fdatasync_cb_count;
static int ftruncate_cb_count;
static int sendfile_cb_count;
static int fstat_cb_count;
static int access_cb_count;
static int chmod_cb_count;
static int fchmod_cb_count;
static int chown_cb_count;
static int fchown_cb_count;
static int lchown_cb_count;
static int link_cb_count;
static int symlink_cb_count;
static int readlink_cb_count;
static int realpath_cb_count;
static int utime_cb_count;
static int futime_cb_count;
static int lutime_cb_count;
static int statfs_cb_count;

static uv_loop_t* loop;

static uv_fs_t open_req1;
static uv_fs_t open_req2;
static uv_fs_t read_req;
static uv_fs_t write_req;
static uv_fs_t unlink_req;
static uv_fs_t close_req;
static uv_fs_t mkdir_req;
static uv_fs_t mkdtemp_req1;
static uv_fs_t mkdtemp_req2;
static uv_fs_t mkstemp_req1;
static uv_fs_t mkstemp_req2;
static uv_fs_t mkstemp_req3;
static uv_fs_t rmdir_req;
static uv_fs_t scandir_req;
static uv_fs_t stat_req;
static uv_fs_t rename_req;
static uv_fs_t fsync_req;
static uv_fs_t fdatasync_req;
static uv_fs_t ftruncate_req;
static uv_fs_t sendfile_req;
static uv_fs_t utime_req;
static uv_fs_t futime_req;

static char buf[32];
static char buf2[32];
static char test_buf[] = "test-buffer\n";
static char test_buf2[] = "second-buffer\n";
static uv_buf_t iov;

int uv_test_getiovmax(void)
{
    return IOV_MAX;
}

static void check_permission(const char* filename, unsigned int mode)
{
    int r;
    uv_fs_t req;
    uv_stat_t* s;

    r = uv_fs_stat(NULL, &req, filename, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);

    s = &req.statbuf;
    ASSERT((s->st_mode & 0777) == mode);

    uv_fs_req_cleanup(&req);
}


static void dummy_cb(uv_fs_t* req)
{
    (void)req;
    dummy_cb_count++;
}


static void link_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_LINK);
    ASSERT_OK(req->result);
    link_cb_count++;
    uv_fs_req_cleanup(req);
}


static void symlink_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_SYMLINK);
    ASSERT_OK(req->result);
    symlink_cb_count++;
    uv_fs_req_cleanup(req);
}

static void readlink_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_READLINK);
    ASSERT_OK(req->result);
    ASSERT_OK(strcmp(req->ptr, "test_file_symlink2"));
    readlink_cb_count++;
    uv_fs_req_cleanup(req);
}


static void realpath_cb(uv_fs_t* req)
{
    char test_file_abs_buf[PATHMAX];
    size_t test_file_abs_size = sizeof(test_file_abs_buf);
    ASSERT_EQ(req->fs_type, UV_FS_REALPATH);
    ASSERT_OK(req->result);

    uv_cwd(test_file_abs_buf, &test_file_abs_size);
    strcat(test_file_abs_buf, "/test_file");
    ASSERT_OK(strcmp(req->ptr, test_file_abs_buf));
    realpath_cb_count++;
    uv_fs_req_cleanup(req);
}


static void access_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_ACCESS);
    access_cb_count++;
    uv_fs_req_cleanup(req);
}


static void fchmod_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_FCHMOD);
    ASSERT_OK(req->result);
    fchmod_cb_count++;
    uv_fs_req_cleanup(req);
    check_permission("test_file", *(int*)req->data);
}


static void chmod_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_CHMOD);
    ASSERT_OK(req->result);
    chmod_cb_count++;
    uv_fs_req_cleanup(req);
    check_permission("test_file", *(int*)req->data);
}


static void fchown_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_FCHOWN);
    ASSERT_OK(req->result);
    fchown_cb_count++;
    uv_fs_req_cleanup(req);
}


static void chown_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_CHOWN);
    ASSERT_OK(req->result);
    chown_cb_count++;
    uv_fs_req_cleanup(req);
}

static void lchown_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_LCHOWN);
    ASSERT_OK(req->result);
    lchown_cb_count++;
    uv_fs_req_cleanup(req);
}

static void chown_root_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_CHOWN);
    /* On unix, chown'ing the root directory is not allowed -
     * unless you're root, of course.
     */
    if (geteuid() == 0)
        ASSERT_OK(req->result);
    else
        ASSERT_EQ(req->result, UV_EPERM);
    chown_cb_count++;
    uv_fs_req_cleanup(req);
}

static void unlink_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &unlink_req);
    ASSERT_EQ(req->fs_type, UV_FS_UNLINK);
    ASSERT_OK(req->result);
    unlink_cb_count++;
    uv_fs_req_cleanup(req);
}

static void fstat_cb(uv_fs_t* req)
{
    uv_stat_t* s = req->ptr;
    ASSERT_EQ(req->fs_type, UV_FS_FSTAT);
    ASSERT_OK(req->result);
    ASSERT_EQ(s->st_size, sizeof(test_buf));
    uv_fs_req_cleanup(req);
    fstat_cb_count++;
}


static void statfs_cb(uv_fs_t* req)
{
    uv_statfs_t* stats;

    ASSERT_EQ(req->fs_type, UV_FS_STATFS);
    ASSERT_OK(req->result);
    ASSERT_NOT_NULL(req->ptr);
    stats = req->ptr;

    ASSERT_UINT64_GT(stats->f_type, 0);

    ASSERT_GT(stats->f_bsize, 0);
    ASSERT_GT(stats->f_blocks, 0);
    ASSERT_LE(stats->f_bfree, stats->f_blocks);
    ASSERT_LE(stats->f_bavail, stats->f_bfree);

    /* There is no assertion for stats->f_files that makes sense, so ignore it.
     */
    ASSERT_LE(stats->f_ffree, stats->f_files);
    uv_fs_req_cleanup(req);
    ASSERT_NULL(req->ptr);
    statfs_cb_count++;
}


static void close_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &close_req);
    ASSERT_EQ(req->fs_type, UV_FS_CLOSE);
    ASSERT_OK(req->result);
    close_cb_count++;
    uv_fs_req_cleanup(req);
    if (close_cb_count == 3) {
        r = uv_fs_unlink(loop, &unlink_req, "test_file2", unlink_cb);
        ASSERT_OK(r);
    }
}


static void ftruncate_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &ftruncate_req);
    ASSERT_EQ(req->fs_type, UV_FS_FTRUNCATE);
    ASSERT_OK(req->result);
    ftruncate_cb_count++;
    uv_fs_req_cleanup(req);
    r = uv_fs_close(loop, &close_req, open_req1.result, close_cb);
    ASSERT_OK(r);
}

static void fail_cb(uv_fs_t* req)
{
    FATAL("fail_cb should not have been called");
}

static void read_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &read_req);
    ASSERT_EQ(req->fs_type, UV_FS_READ);
    ASSERT_GE(req->result, 0); /* FIXME(bnoordhuis) Check if requested size? */
    read_cb_count++;
    uv_fs_req_cleanup(req);
    if (read_cb_count == 1) {
        ASSERT_OK(strcmp(buf, test_buf));
        r = uv_fs_ftruncate(
            loop, &ftruncate_req, open_req1.result, 7, ftruncate_cb);
    } else {
        ASSERT_OK(strcmp(buf, "test-bu"));
        r = uv_fs_close(loop, &close_req, open_req1.result, close_cb);
    }
    ASSERT_OK(r);
}


static void open_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &open_req1);
    ASSERT_EQ(req->fs_type, UV_FS_OPEN);
    if (req->result < 0) {
        fprintf(stderr, "async open error: %d\n", (int)req->result);
        ASSERT(0);
    }
    open_cb_count++;
    ASSERT(req->path);
    ASSERT_OK(memcmp(req->path, "test_file2\0", 11));
    uv_fs_req_cleanup(req);
    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(loop, &read_req, open_req1.result, &iov, 1, -1, read_cb);
    ASSERT_OK(r);
}


static void open_cb_simple(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_OPEN);
    if (req->result < 0) {
        fprintf(stderr, "async open error: %d\n", (int)req->result);
        ASSERT(0);
    }
    open_cb_count++;
    ASSERT(req->path);
    uv_fs_req_cleanup(req);
}


static void fsync_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &fsync_req);
    ASSERT_EQ(req->fs_type, UV_FS_FSYNC);
    ASSERT_OK(req->result);
    fsync_cb_count++;
    uv_fs_req_cleanup(req);
    r = uv_fs_close(loop, &close_req, open_req1.result, close_cb);
    ASSERT_OK(r);
}


static void fdatasync_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &fdatasync_req);
    ASSERT_EQ(req->fs_type, UV_FS_FDATASYNC);
    ASSERT_OK(req->result);
    fdatasync_cb_count++;
    uv_fs_req_cleanup(req);
    r = uv_fs_fsync(loop, &fsync_req, open_req1.result, fsync_cb);
    ASSERT_OK(r);
}


static void write_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &write_req);
    ASSERT_EQ(req->fs_type, UV_FS_WRITE);
    ASSERT_GE(req->result, 0); /* FIXME(bnoordhuis) Check if requested size? */
    write_cb_count++;
    uv_fs_req_cleanup(req);
    r = uv_fs_fdatasync(loop, &fdatasync_req, open_req1.result, fdatasync_cb);
    ASSERT_OK(r);
}


static void create_cb(uv_fs_t* req)
{
    int r;
    ASSERT_PTR_EQ(req, &open_req1);
    ASSERT_EQ(req->fs_type, UV_FS_OPEN);
    ASSERT_GE(req->result, 0);
    create_cb_count++;
    uv_fs_req_cleanup(req);
    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(loop, &write_req, req->result, &iov, 1, -1, write_cb);
    ASSERT_OK(r);
}


static void rename_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &rename_req);
    ASSERT_EQ(req->fs_type, UV_FS_RENAME);
    ASSERT_OK(req->result);
    rename_cb_count++;
    uv_fs_req_cleanup(req);
}


static void mkdir_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &mkdir_req);
    ASSERT_EQ(req->fs_type, UV_FS_MKDIR);
    ASSERT_OK(req->result);
    mkdir_cb_count++;
    ASSERT(req->path);
    ASSERT_OK(memcmp(req->path, "test_dir\0", 9));
    uv_fs_req_cleanup(req);
}


static void check_mkdtemp_result(uv_fs_t* req)
{
    int r;

    ASSERT_EQ(req->fs_type, UV_FS_MKDTEMP);
    ASSERT_OK(req->result);
    ASSERT(req->path);
    ASSERT_EQ(15, strlen(req->path));
    ASSERT_OK(memcmp(req->path, "test_dir_", 9));
    ASSERT_NE(0, memcmp(req->path + 9, "XXXXXX", 6));
    check_permission(req->path, 0700);

    /* Check if req->path is actually a directory */
    r = uv_fs_stat(NULL, &stat_req, req->path, NULL);
    ASSERT_OK(r);
    ASSERT(((uv_stat_t*)stat_req.ptr)->st_mode & S_IFDIR);
    uv_fs_req_cleanup(&stat_req);
}


static void mkdtemp_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &mkdtemp_req1);
    check_mkdtemp_result(req);
    mkdtemp_cb_count++;
}


static void check_mkstemp_result(uv_fs_t* req)
{
    int r;

    ASSERT_EQ(req->fs_type, UV_FS_MKSTEMP);
    ASSERT_GE(req->result, 0);
    ASSERT(req->path);
    ASSERT_EQ(16, strlen(req->path));
    ASSERT_OK(memcmp(req->path, "test_file_", 10));
    ASSERT_NE(0, memcmp(req->path + 10, "XXXXXX", 6));
    check_permission(req->path, 0600);

    /* Check if req->path is actually a file */
    r = uv_fs_stat(NULL, &stat_req, req->path, NULL);
    ASSERT_OK(r);
    ASSERT(stat_req.statbuf.st_mode & S_IFREG);
    uv_fs_req_cleanup(&stat_req);
}


static void mkstemp_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &mkstemp_req1);
    check_mkstemp_result(req);
    mkstemp_cb_count++;
}


static void rmdir_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &rmdir_req);
    ASSERT_EQ(req->fs_type, UV_FS_RMDIR);
    ASSERT_OK(req->result);
    rmdir_cb_count++;
    ASSERT(req->path);
    ASSERT_OK(memcmp(req->path, "test_dir\0", 9));
    uv_fs_req_cleanup(req);
}


static void assert_is_file_type(uv_dirent_t dent)
{
    /*
     * For Apple and Windows, we know getdents is expected to work but for other
     * environments, the filesystem dictates whether or not getdents supports
     * returning the file type.
     *
     *   See:
     *     http://man7.org/linux/man-pages/man2/getdents.2.html
     *     https://github.com/libuv/libuv/issues/501
     */
    ASSERT(dent.type == UV_DIRENT_FILE || dent.type == UV_DIRENT_UNKNOWN);
}


static void scandir_cb(uv_fs_t* req)
{
    uv_dirent_t dent;
    ASSERT_PTR_EQ(req, &scandir_req);
    ASSERT_EQ(req->fs_type, UV_FS_SCANDIR);
    ASSERT_EQ(2, req->result);
    ASSERT(req->ptr);

    while (UV_EOF != uv_fs_scandir_next(req, &dent)) {
        ASSERT(strcmp(dent.name, "file1") == 0 ||
               strcmp(dent.name, "file2") == 0);
        assert_is_file_type(dent);
    }
    scandir_cb_count++;
    ASSERT(req->path);
    ASSERT_OK(memcmp(req->path, "test_dir\0", 9));
    uv_fs_req_cleanup(req);
    ASSERT(!req->ptr);
}


static void empty_scandir_cb(uv_fs_t* req)
{
    uv_dirent_t dent;

    ASSERT_PTR_EQ(req, &scandir_req);
    ASSERT_EQ(req->fs_type, UV_FS_SCANDIR);
    ASSERT_OK(req->result);
    ASSERT_NULL(req->ptr);
    ASSERT_EQ(UV_EOF, uv_fs_scandir_next(req, &dent));
    uv_fs_req_cleanup(req);
    scandir_cb_count++;
}

static void non_existent_scandir_cb(uv_fs_t* req)
{
    uv_dirent_t dent;

    ASSERT_PTR_EQ(req, &scandir_req);
    ASSERT_EQ(req->fs_type, UV_FS_SCANDIR);
    ASSERT_EQ(req->result, UV_ENOENT);
    ASSERT_NULL(req->ptr);
    ASSERT_EQ(UV_ENOENT, uv_fs_scandir_next(req, &dent));
    uv_fs_req_cleanup(req);
    scandir_cb_count++;
}


static void file_scandir_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &scandir_req);
    ASSERT_EQ(req->fs_type, UV_FS_SCANDIR);
    ASSERT_EQ(req->result, UV_ENOTDIR);
    ASSERT_NULL(req->ptr);
    uv_fs_req_cleanup(req);
    scandir_cb_count++;
}


static void stat_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &stat_req);
    ASSERT(req->fs_type == UV_FS_STAT || req->fs_type == UV_FS_LSTAT);
    ASSERT_OK(req->result);
    ASSERT(req->ptr);
    stat_cb_count++;
    uv_fs_req_cleanup(req);
    ASSERT(!req->ptr);
}

static void stat_batch_cb(uv_fs_t* req)
{
    ASSERT(req->fs_type == UV_FS_STAT || req->fs_type == UV_FS_LSTAT);
    ASSERT_OK(req->result);
    ASSERT(req->ptr);
    stat_cb_count++;
    uv_fs_req_cleanup(req);
    ASSERT(!req->ptr);
}


static void sendfile_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &sendfile_req);
    ASSERT_EQ(req->fs_type, UV_FS_SENDFILE);
    ASSERT_EQ(65545, req->result);
    sendfile_cb_count++;
    uv_fs_req_cleanup(req);
}


static void sendfile_nodata_cb(uv_fs_t* req)
{
    ASSERT_PTR_EQ(req, &sendfile_req);
    ASSERT_EQ(req->fs_type, UV_FS_SENDFILE);
    ASSERT_OK(req->result);
    sendfile_cb_count++;
    uv_fs_req_cleanup(req);
}


static void open_noent_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_OPEN);
    ASSERT_EQ(req->result, UV_ENOENT);
    open_cb_count++;
    uv_fs_req_cleanup(req);
}

static void open_nametoolong_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_OPEN);
    ASSERT_EQ(req->result, UV_ENAMETOOLONG);
    open_cb_count++;
    uv_fs_req_cleanup(req);
}

static void open_loop_cb(uv_fs_t* req)
{
    ASSERT_EQ(req->fs_type, UV_FS_OPEN);
    ASSERT_EQ(req->result, UV_ELOOP);
    open_cb_count++;
    uv_fs_req_cleanup(req);
}


TEST_IMPL(fs_file_noent)
{
    uv_fs_t req;
    int r;

    loop = uv_default_loop();

    r = uv_fs_open(NULL, &req, "does_not_exist", UV_FS_O_RDONLY, 0, NULL);
    ASSERT_EQ(r, UV_ENOENT);
    ASSERT_EQ(req.result, UV_ENOENT);
    uv_fs_req_cleanup(&req);

    r = uv_fs_open(
        loop, &req, "does_not_exist", UV_FS_O_RDONLY, 0, open_noent_cb);
    ASSERT_OK(r);

    ASSERT_OK(open_cb_count);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, open_cb_count);

    /* TODO add EACCES test */

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_file_nametoolong)
{
    uv_fs_t req;
    int r;
    char name[TOO_LONG_NAME_LENGTH + 1];

    loop = uv_default_loop();

    memset(name, 'a', TOO_LONG_NAME_LENGTH);
    name[TOO_LONG_NAME_LENGTH] = 0;

    r = uv_fs_open(NULL, &req, name, UV_FS_O_RDONLY, 0, NULL);
    ASSERT_EQ(r, UV_ENAMETOOLONG);
    ASSERT_EQ(req.result, UV_ENAMETOOLONG);
    uv_fs_req_cleanup(&req);

    r = uv_fs_open(loop, &req, name, UV_FS_O_RDONLY, 0, open_nametoolong_cb);
    ASSERT_OK(r);

    ASSERT_OK(open_cb_count);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, open_cb_count);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_file_loop)
{
    uv_fs_t req;
    int r;

    loop = uv_default_loop();

    unlink("test_symlink");
    r = uv_fs_symlink(NULL, &req, "test_symlink", "test_symlink", 0, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&req);

    r = uv_fs_open(NULL, &req, "test_symlink", UV_FS_O_RDONLY, 0, NULL);
    ASSERT_EQ(r, UV_ELOOP);
    ASSERT_EQ(req.result, UV_ELOOP);
    uv_fs_req_cleanup(&req);

    r = uv_fs_open(loop, &req, "test_symlink", UV_FS_O_RDONLY, 0, open_loop_cb);
    ASSERT_OK(r);

    ASSERT_OK(open_cb_count);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, open_cb_count);

    unlink("test_symlink");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

static void check_utime(const char* path, double atime, double mtime,
                        int test_lutime)
{
    uv_stat_t* s;
    uv_fs_t req;
    int r;

    if (test_lutime)
        r = uv_fs_lstat(loop, &req, path, NULL);
    else
        r = uv_fs_stat(loop, &req, path, NULL);

    ASSERT_OK(r);

    ASSERT_OK(req.result);
    s = &req.statbuf;

    if (s->st_atim.tv_nsec == 0 && s->st_mtim.tv_nsec == 0) {
        /*
         * Test sub-second timestamps only when supported (such as Windows with
         * NTFS). Some other platforms support sub-second timestamps, but that
         * support is filesystem-dependent. Notably OS X (HFS Plus) does NOT
         * support sub-second timestamps. But kernels may round or truncate in
         * either direction, so we may accept either possible answer.
         */
        if (atime > 0 || (long)atime == atime)
            ASSERT_EQ(s->st_atim.tv_sec, (long)atime);
        if (mtime > 0 || (long)mtime == mtime)
            ASSERT_EQ(s->st_mtim.tv_sec, (long)mtime);
        ASSERT_GE(s->st_atim.tv_sec, (long)atime - 1);
        ASSERT_GE(s->st_mtim.tv_sec, (long)mtime - 1);
        ASSERT_LE(s->st_atim.tv_sec, (long)atime);
        ASSERT_LE(s->st_mtim.tv_sec, (long)mtime);
    } else {
        double st_atim;
        double st_mtim;
        /* TODO(vtjnash): would it be better to normalize this? */
        ASSERT_DOUBLE_GE(s->st_atim.tv_nsec, 0);
        ASSERT_DOUBLE_GE(s->st_mtim.tv_nsec, 0);
        st_atim = s->st_atim.tv_sec + s->st_atim.tv_nsec / 1e9;
        st_mtim = s->st_mtim.tv_sec + s->st_mtim.tv_nsec / 1e9;
        /*
         * Linux does not allow reading reliably the atime of a symlink
         * since readlink() can update it
         */
        if (!test_lutime)
            ASSERT_DOUBLE_EQ(st_atim, atime);
        ASSERT_DOUBLE_EQ(st_mtim, mtime);
    }

    uv_fs_req_cleanup(&req);
}


static void utime_cb(uv_fs_t* req)
{
    utime_check_t* c;

    ASSERT_PTR_EQ(req, &utime_req);
    ASSERT_OK(req->result);
    ASSERT_EQ(req->fs_type, UV_FS_UTIME);

    c = req->data;
    check_utime(c->path, c->atime, c->mtime, /* test_lutime */ 0);

    uv_fs_req_cleanup(req);
    utime_cb_count++;
}


static void futime_cb(uv_fs_t* req)
{
    utime_check_t* c;

    ASSERT_PTR_EQ(req, &futime_req);
    ASSERT_OK(req->result);
    ASSERT_EQ(req->fs_type, UV_FS_FUTIME);

    c = req->data;
    check_utime(c->path, c->atime, c->mtime, /* test_lutime */ 0);

    uv_fs_req_cleanup(req);
    futime_cb_count++;
}


static void lutime_cb(uv_fs_t* req)
{
    utime_check_t* c;

    ASSERT_OK(req->result);
    ASSERT_EQ(req->fs_type, UV_FS_LUTIME);

    c = req->data;
    check_utime(c->path, c->atime, c->mtime, /* test_lutime */ 1);

    uv_fs_req_cleanup(req);
    lutime_cb_count++;
}


TEST_IMPL(fs_file_async)
{
    int r;

    /* Setup. */
    unlink("test_file");
    unlink("test_file2");

    loop = uv_default_loop();

    r = uv_fs_open(loop,
                   &open_req1,
                   "test_file",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IRUSR | S_IWUSR,
                   create_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(1, create_cb_count);
    ASSERT_EQ(1, write_cb_count);
    ASSERT_EQ(1, fsync_cb_count);
    ASSERT_EQ(1, fdatasync_cb_count);
    ASSERT_EQ(1, close_cb_count);

    r = uv_fs_rename(loop, &rename_req, "test_file", "test_file2", rename_cb);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, create_cb_count);
    ASSERT_EQ(1, write_cb_count);
    ASSERT_EQ(1, close_cb_count);
    ASSERT_EQ(1, rename_cb_count);

    r = uv_fs_open(loop, &open_req1, "test_file2", UV_FS_O_RDWR, 0, open_cb);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, open_cb_count);
    ASSERT_EQ(1, read_cb_count);
    ASSERT_EQ(2, close_cb_count);
    ASSERT_EQ(1, rename_cb_count);
    ASSERT_EQ(1, create_cb_count);
    ASSERT_EQ(1, write_cb_count);
    ASSERT_EQ(1, ftruncate_cb_count);

    r = uv_fs_open(loop, &open_req1, "test_file2", UV_FS_O_RDONLY, 0, open_cb);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(2, open_cb_count);
    ASSERT_EQ(2, read_cb_count);
    ASSERT_EQ(3, close_cb_count);
    ASSERT_EQ(1, rename_cb_count);
    ASSERT_EQ(1, unlink_cb_count);
    ASSERT_EQ(1, create_cb_count);
    ASSERT_EQ(1, write_cb_count);
    ASSERT_EQ(1, ftruncate_cb_count);

    /* Cleanup. */
    unlink("test_file");
    unlink("test_file2");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


static void fs_file_sync(int add_flags)
{
    int r;

    /* Setup. */
    unlink("test_file");
    unlink("test_file2");

    loop = uv_default_loop();

    r = uv_fs_open(loop,
                   &open_req1,
                   "test_file",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT | add_flags,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(write_req.result, 0);
    uv_fs_req_cleanup(&write_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(
        NULL, &open_req1, "test_file", UV_FS_O_RDWR | add_flags, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(read_req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_ftruncate(NULL, &ftruncate_req, open_req1.result, 7, NULL);
    ASSERT_OK(r);
    ASSERT_OK(ftruncate_req.result);
    uv_fs_req_cleanup(&ftruncate_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_rename(NULL, &rename_req, "test_file", "test_file2", NULL);
    ASSERT_OK(r);
    ASSERT_OK(rename_req.result);
    uv_fs_req_cleanup(&rename_req);

    r = uv_fs_open(
        NULL, &open_req1, "test_file2", UV_FS_O_RDONLY | add_flags, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(read_req.result, 0);
    ASSERT_OK(strcmp(buf, "test-bu"));
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_unlink(NULL, &unlink_req, "test_file2", NULL);
    ASSERT_OK(r);
    ASSERT_OK(unlink_req.result);
    uv_fs_req_cleanup(&unlink_req);

    /* Cleanup */
    unlink("test_file");
    unlink("test_file2");
}
TEST_IMPL(fs_file_sync)
{
    fs_file_sync(0);
    fs_file_sync(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


static void fs_file_write_null_buffer(int add_flags)
{
    int r;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT | add_flags,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(NULL, 0);
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_OK(r);
    ASSERT_OK(write_req.result);
    uv_fs_req_cleanup(&write_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    unlink("test_file");
}
TEST_IMPL(fs_file_write_null_buffer)
{
    fs_file_write_null_buffer(0);
    fs_file_write_null_buffer(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_async_dir)
{
    int r;
    uv_dirent_t dent;

    /* Setup */
    unlink("test_dir/file1");
    unlink("test_dir/file2");
    rmdir("test_dir");

    loop = uv_default_loop();

    r = uv_fs_mkdir(loop, &mkdir_req, "test_dir", 0755, mkdir_cb);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, mkdir_cb_count);

    /* Create 2 files synchronously. */
    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_dir/file1",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    uv_fs_req_cleanup(&open_req1);
    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_dir/file2",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    uv_fs_req_cleanup(&open_req1);
    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_scandir(loop, &scandir_req, "test_dir", 0, scandir_cb);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, scandir_cb_count);

    /* sync uv_fs_scandir */
    r = uv_fs_scandir(NULL, &scandir_req, "test_dir", 0, NULL);
    ASSERT_EQ(2, r);
    ASSERT_EQ(2, scandir_req.result);
    ASSERT(scandir_req.ptr);
    while (UV_EOF != uv_fs_scandir_next(&scandir_req, &dent)) {
        ASSERT(strcmp(dent.name, "file1") == 0 ||
               strcmp(dent.name, "file2") == 0);
        assert_is_file_type(dent);
    }
    uv_fs_req_cleanup(&scandir_req);
    ASSERT(!scandir_req.ptr);

    r = uv_fs_stat(loop, &stat_req, "test_dir", stat_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);

    r = uv_fs_stat(loop, &stat_req, "test_dir/", stat_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);

    r = uv_fs_lstat(loop, &stat_req, "test_dir", stat_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);

    r = uv_fs_lstat(loop, &stat_req, "test_dir/", stat_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(4, stat_cb_count);

    r = uv_fs_unlink(loop, &unlink_req, "test_dir/file1", unlink_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, unlink_cb_count);

    r = uv_fs_unlink(loop, &unlink_req, "test_dir/file2", unlink_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(2, unlink_cb_count);

    r = uv_fs_rmdir(loop, &rmdir_req, "test_dir", rmdir_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, rmdir_cb_count);

    /* Cleanup */
    unlink("test_dir/file1");
    unlink("test_dir/file2");
    rmdir("test_dir");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


static int test_sendfile(void (*setup)(int), uv_fs_cb cb, size_t expected_size)
{
    int f, r;
    struct stat s1, s2;
    uv_fs_t req;
    char buf1[1];

    loop = uv_default_loop();

    /* Setup. */
    unlink("test_file");
    unlink("test_file2");

    f = open("test_file", UV_FS_O_WRONLY | UV_FS_O_CREAT, S_IWUSR | S_IRUSR);
    ASSERT_NE(f, -1);

    if (setup != NULL)
        setup(f);

    r = close(f);
    ASSERT_OK(r);

    /* Test starts here. */
    r = uv_fs_open(NULL, &open_req1, "test_file", UV_FS_O_RDWR, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    r = uv_fs_open(NULL,
                   &open_req2,
                   "test_file2",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req2.result, 0);
    uv_fs_req_cleanup(&open_req2);

    r = uv_fs_sendfile(
        loop, &sendfile_req, open_req2.result, open_req1.result, 1, 131072, cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);

    ASSERT_EQ(1, sendfile_cb_count);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);
    r = uv_fs_close(NULL, &close_req, open_req2.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);

    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));
    ASSERT_OK(stat("test_file", &s1));
    ASSERT_OK(stat("test_file2", &s2));
    ASSERT_EQ(s2.st_size, expected_size);

    if (expected_size > 0) {
        ASSERT_UINT64_EQ(s1.st_size, s2.st_size + 1);
        r = uv_fs_open(NULL, &open_req1, "test_file2", UV_FS_O_RDWR, 0, NULL);
        ASSERT_GE(r, 0);
        ASSERT_GE(open_req1.result, 0);
        uv_fs_req_cleanup(&open_req1);

        memset(buf1, 0, sizeof(buf1));
        iov = uv_buf_init(buf1, sizeof(buf1));
        r = uv_fs_read(NULL, &req, open_req1.result, &iov, 1, -1, NULL);
        ASSERT_GE(r, 0);
        ASSERT_GE(req.result, 0);
        ASSERT_EQ(buf1[0], 'e'); /* 'e' from begin */
        uv_fs_req_cleanup(&req);
    } else {
        ASSERT_UINT64_EQ(s1.st_size, s2.st_size);
    }

    /* Cleanup. */
    unlink("test_file");
    unlink("test_file2");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


static void sendfile_setup(int f)
{
    ASSERT_EQ(6, write(f, "begin\n", 6));
    ASSERT_EQ(65542, lseek(f, 65536, SEEK_CUR));
    ASSERT_EQ(4, write(f, "end\n", 4));
}


TEST_IMPL(fs_async_sendfile)
{
    return test_sendfile(sendfile_setup, sendfile_cb, 65545);
}


TEST_IMPL(fs_async_sendfile_nodata)
{
    return test_sendfile(NULL, sendfile_nodata_cb, 0);
}


TEST_IMPL(fs_mkdtemp)
{
    int r;
    const char* path_template = "test_dir_XXXXXX";

    loop = uv_default_loop();

    r = uv_fs_mkdtemp(loop, &mkdtemp_req1, path_template, mkdtemp_cb);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, mkdtemp_cb_count);

    /* sync mkdtemp */
    r = uv_fs_mkdtemp(NULL, &mkdtemp_req2, path_template, NULL);
    ASSERT_OK(r);
    check_mkdtemp_result(&mkdtemp_req2);

    /* mkdtemp return different values on subsequent calls */
    ASSERT_NE(0, strcmp(mkdtemp_req1.path, mkdtemp_req2.path));

    /* Cleanup */
    rmdir(mkdtemp_req1.path);
    rmdir(mkdtemp_req2.path);
    uv_fs_req_cleanup(&mkdtemp_req1);
    uv_fs_req_cleanup(&mkdtemp_req2);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_mkstemp)
{
    int r;
    int fd;
    const char path_template[] = "test_file_XXXXXX";
    uv_fs_t req;

    loop = uv_default_loop();

    r = uv_fs_mkstemp(loop, &mkstemp_req1, path_template, mkstemp_cb);
    ASSERT_OK(r);

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, mkstemp_cb_count);

    /* sync mkstemp */
    r = uv_fs_mkstemp(NULL, &mkstemp_req2, path_template, NULL);
    ASSERT_GE(r, 0);
    check_mkstemp_result(&mkstemp_req2);

    /* mkstemp return different values on subsequent calls */
    ASSERT_NE(0, strcmp(mkstemp_req1.path, mkstemp_req2.path));

    /* invalid template returns EINVAL */
    ASSERT_EQ(UV_EINVAL, uv_fs_mkstemp(NULL, &mkstemp_req3, "test_file", NULL));

    /* Make sure that path is empty string */
    ASSERT_OK(strlen(mkstemp_req3.path));

    uv_fs_req_cleanup(&mkstemp_req3);

    /* We can write to the opened file */
    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &req, mkstemp_req1.result, &iov, 1, -1, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_EQ(req.result, sizeof(test_buf));
    uv_fs_req_cleanup(&req);

    /* Cleanup */
    uv_fs_close(NULL, &req, mkstemp_req1.result, NULL);
    uv_fs_req_cleanup(&req);
    uv_fs_close(NULL, &req, mkstemp_req2.result, NULL);
    uv_fs_req_cleanup(&req);

    fd = uv_fs_open(NULL, &req, mkstemp_req1.path, UV_FS_O_RDONLY, 0, NULL);
    ASSERT_GE(fd, 0);
    uv_fs_req_cleanup(&req);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &req, fd, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));
    uv_fs_req_cleanup(&req);

    uv_fs_close(NULL, &req, fd, NULL);
    uv_fs_req_cleanup(&req);

    unlink(mkstemp_req1.path);
    unlink(mkstemp_req2.path);
    uv_fs_req_cleanup(&mkstemp_req1);
    uv_fs_req_cleanup(&mkstemp_req2);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_fstat)
{
    int r;
    uv_fs_t req;
    uv_file file;
    uv_stat_t* s;
    struct stat t;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &req,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result;
    uv_fs_req_cleanup(&req);

    memset(&t, 0, sizeof(t));
    ASSERT_OK(fstat(file, &t));
    ASSERT_OK(uv_fs_fstat(NULL, &req, file, NULL));
    ASSERT_OK(req.result);
    s = req.ptr;
    /* If statx() is supported, the birth time should be equal to the change
     * time because we just created the file. On older kernels, it's set to
     * zero.
     */
    ASSERT(s->st_birthtim.tv_sec == 0 ||
           s->st_birthtim.tv_sec == t.st_ctim.tv_sec);
    ASSERT(s->st_birthtim.tv_nsec == 0 ||
           s->st_birthtim.tv_nsec == t.st_ctim.tv_nsec);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &req, file, &iov, 1, -1, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_EQ(req.result, sizeof(test_buf));
    uv_fs_req_cleanup(&req);

    memset(&req.statbuf, 0xaa, sizeof(req.statbuf));
    r = uv_fs_fstat(NULL, &req, file, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    s = req.ptr;
    ASSERT_EQ(s->st_size, sizeof(test_buf));

    r = fstat(file, &t);
    ASSERT_OK(r);

    ASSERT_EQ(s->st_dev, (uint64_t)t.st_dev);
    ASSERT_EQ(s->st_mode, (uint64_t)t.st_mode);
    ASSERT_EQ(s->st_nlink, (uint64_t)t.st_nlink);
    ASSERT_EQ(s->st_uid, (uint64_t)t.st_uid);
    ASSERT_EQ(s->st_gid, (uint64_t)t.st_gid);
    ASSERT_EQ(s->st_rdev, (uint64_t)t.st_rdev);
    ASSERT_EQ(s->st_ino, (uint64_t)t.st_ino);
    ASSERT_EQ(s->st_size, (uint64_t)t.st_size);
    ASSERT_EQ(s->st_blksize, (uint64_t)t.st_blksize);
    ASSERT_EQ(s->st_blocks, (uint64_t)t.st_blocks);
    ASSERT_EQ(s->st_atim.tv_sec, t.st_atim.tv_sec);
    ASSERT_EQ(s->st_atim.tv_nsec, t.st_atim.tv_nsec);
    ASSERT_EQ(s->st_mtim.tv_sec, t.st_mtim.tv_sec);
    ASSERT_EQ(s->st_mtim.tv_nsec, t.st_mtim.tv_nsec);
    ASSERT_EQ(s->st_ctim.tv_sec, t.st_ctim.tv_sec);
    ASSERT_EQ(s->st_ctim.tv_nsec, t.st_ctim.tv_nsec);

    ASSERT_OK(s->st_flags);
    ASSERT_OK(s->st_gen);

    uv_fs_req_cleanup(&req);

    /* Now do the uv_fs_fstat call asynchronously */
    r = uv_fs_fstat(loop, &req, file, fstat_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, fstat_cb_count);


    r = uv_fs_close(NULL, &req, file, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /*
     * Run the loop just to check we don't have make any extraneous uv_ref()
     * calls. This should drop out immediately.
     */
    uv_run(loop, UV_RUN_DEFAULT);

    /* Cleanup. */
    unlink("test_file");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_fstat_stdio)
{
    int fd;
    int res;
    uv_fs_t req;

    for (fd = 0; fd <= 2; ++fd) {
        res = uv_fs_fstat(NULL, &req, fd, NULL);
        ASSERT_OK(res);
        ASSERT_OK(req.result);

        uv_fs_req_cleanup(&req);
    }

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


TEST_IMPL(fs_access)
{
    int r;
    uv_fs_t req;
    uv_file file;

    /* Setup. */
    unlink("test_file");
    rmdir("test_dir");

    loop = uv_default_loop();

    /* File should not exist */
    r = uv_fs_access(NULL, &req, "test_file", F_OK, NULL);
    ASSERT_LT(r, 0);
    ASSERT_LT(req.result, 0);
    uv_fs_req_cleanup(&req);

    /* File should not exist */
    r = uv_fs_access(loop, &req, "test_file", F_OK, access_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, access_cb_count);
    access_cb_count = 0; /* reset for the next test */

    /* Create file */
    r = uv_fs_open(NULL,
                   &req,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result;
    uv_fs_req_cleanup(&req);

    /* File should exist */
    r = uv_fs_access(NULL, &req, "test_file", F_OK, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /* File should exist */
    r = uv_fs_access(loop, &req, "test_file", F_OK, access_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, access_cb_count);
    access_cb_count = 0; /* reset for the next test */

    /* Close file */
    r = uv_fs_close(NULL, &req, file, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /* Directory access */
    r = uv_fs_mkdir(NULL, &req, "test_dir", 0777, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&req);

    r = uv_fs_access(NULL, &req, "test_dir", W_OK, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /*
     * Run the loop just to check we don't have make any extraneous uv_ref()
     * calls. This should drop out immediately.
     */
    uv_run(loop, UV_RUN_DEFAULT);

    /* Cleanup. */
    unlink("test_file");
    rmdir("test_dir");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_chmod)
{
    int r;
    uv_fs_t req;
    uv_file file;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &req,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result;
    uv_fs_req_cleanup(&req);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &req, file, &iov, 1, -1, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_EQ(req.result, sizeof(test_buf));
    uv_fs_req_cleanup(&req);

    /* Make the file write-only */
    r = uv_fs_chmod(NULL, &req, "test_file", 0200, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    check_permission("test_file", 0200);

    /* Make the file read-only */
    r = uv_fs_chmod(NULL, &req, "test_file", 0400, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    check_permission("test_file", 0400);

    /* Make the file read+write with sync uv_fs_fchmod */
    r = uv_fs_fchmod(NULL, &req, file, 0600, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    check_permission("test_file", 0600);

    /* async chmod */
    {
        static int mode = 0200;
        req.data = &mode;
    }
    r = uv_fs_chmod(loop, &req, "test_file", 0200, chmod_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, chmod_cb_count);
    chmod_cb_count = 0; /* reset for the next test */

    /* async chmod */
    {
        static int mode = 0400;
        req.data = &mode;
    }
    r = uv_fs_chmod(loop, &req, "test_file", 0400, chmod_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, chmod_cb_count);

    /* async fchmod */
    {
        static int mode = 0600;
        req.data = &mode;
    }
    r = uv_fs_fchmod(loop, &req, file, 0600, fchmod_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, fchmod_cb_count);

    uv_fs_close(loop, &req, file, NULL);

    /*
     * Run the loop just to check we don't have make any extraneous uv_ref()
     * calls. This should drop out immediately.
     */
    uv_run(loop, UV_RUN_DEFAULT);

    /* Cleanup. */
    unlink("test_file");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_unlink_readonly)
{
    int r;
    uv_fs_t req;
    uv_file file;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &req,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result;
    uv_fs_req_cleanup(&req);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &req, file, &iov, 1, -1, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_EQ(req.result, sizeof(test_buf));
    uv_fs_req_cleanup(&req);

    uv_fs_close(loop, &req, file, NULL);

    /* Make the file read-only */
    r = uv_fs_chmod(NULL, &req, "test_file", 0400, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    check_permission("test_file", 0400);

    /* Try to unlink the file */
    r = uv_fs_unlink(NULL, &req, "test_file", NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /*
     * Run the loop just to check we don't have make any extraneous uv_ref()
     * calls. This should drop out immediately.
     */
    uv_run(loop, UV_RUN_DEFAULT);

    /* Cleanup. */
    uv_fs_chmod(NULL, &req, "test_file", 0600, NULL);
    uv_fs_req_cleanup(&req);
    unlink("test_file");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_chown)
{
    int r;
    uv_fs_t req;
    uv_file file;

    /* Setup. */
    unlink("test_file");
    unlink("test_file_link");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &req,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result;
    uv_fs_req_cleanup(&req);

    /* sync chown */
    r = uv_fs_chown(NULL, &req, "test_file", -1, -1, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /* sync fchown */
    r = uv_fs_fchown(NULL, &req, file, -1, -1, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /* async chown */
    r = uv_fs_chown(loop, &req, "test_file", -1, -1, chown_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, chown_cb_count);

    /* chown to root (fail) */
    chown_cb_count = 0;
    r = uv_fs_chown(loop, &req, "test_file", 0, 0, chown_root_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, chown_cb_count);

    /* async fchown */
    r = uv_fs_fchown(loop, &req, file, -1, -1, fchown_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, fchown_cb_count);

    /* Haiku doesn't support hardlink */
    /* sync link */
    r = uv_fs_link(NULL, &req, "test_file", "test_file_link", NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /* sync lchown */
    r = uv_fs_lchown(NULL, &req, "test_file_link", -1, -1, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /* async lchown */
    r = uv_fs_lchown(loop, &req, "test_file_link", -1, -1, lchown_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, lchown_cb_count);

    /* Close file */
    r = uv_fs_close(NULL, &req, file, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /*
     * Run the loop just to check we don't have make any extraneous uv_ref()
     * calls. This should drop out immediately.
     */
    uv_run(loop, UV_RUN_DEFAULT);

    /* Cleanup. */
    unlink("test_file");
    unlink("test_file_link");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_link)
{
    int r;
    uv_fs_t req;
    uv_file file;
    uv_file link;

    /* Setup. */
    unlink("test_file");
    unlink("test_file_link");
    unlink("test_file_link2");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &req,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result;
    uv_fs_req_cleanup(&req);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &req, file, &iov, 1, -1, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_EQ(req.result, sizeof(test_buf));
    uv_fs_req_cleanup(&req);

    uv_fs_close(loop, &req, file, NULL);

    /* sync link */
    r = uv_fs_link(NULL, &req, "test_file", "test_file_link", NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    r = uv_fs_open(NULL, &req, "test_file_link", UV_FS_O_RDWR, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    link = req.result;
    uv_fs_req_cleanup(&req);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &req, link, &iov, 1, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));

    close(link);

    /* async link */
    r = uv_fs_link(loop, &req, "test_file", "test_file_link2", link_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, link_cb_count);

    r = uv_fs_open(NULL, &req, "test_file_link2", UV_FS_O_RDWR, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    link = req.result;
    uv_fs_req_cleanup(&req);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &req, link, &iov, 1, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));

    uv_fs_close(loop, &req, link, NULL);

    /*
     * Run the loop just to check we don't have make any extraneous uv_ref()
     * calls. This should drop out immediately.
     */
    uv_run(loop, UV_RUN_DEFAULT);

    /* Cleanup. */
    unlink("test_file");
    unlink("test_file_link");
    unlink("test_file_link2");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_readlink)
{
    /* Must return UV_ENOENT on an inexistent file */
    {
        uv_fs_t req;

        loop = uv_default_loop();
        ASSERT_OK(uv_fs_readlink(loop, &req, "no_such_file", dummy_cb));
        ASSERT_OK(uv_run(loop, UV_RUN_DEFAULT));
        ASSERT_EQ(1, dummy_cb_count);
        ASSERT_NULL(req.ptr);
        ASSERT_EQ(req.result, UV_ENOENT);
        uv_fs_req_cleanup(&req);

        ASSERT_EQ(UV_ENOENT, uv_fs_readlink(NULL, &req, "no_such_file", NULL));
        ASSERT_NULL(req.ptr);
        ASSERT_EQ(req.result, UV_ENOENT);
        uv_fs_req_cleanup(&req);
    }

    /* Must return UV_EINVAL on a non-symlink file */
    {
        int r;
        uv_fs_t req;
        uv_file file;

        /* Setup */

        /* Create a non-symlink file */
        r = uv_fs_open(NULL,
                       &req,
                       "test_file",
                       UV_FS_O_RDWR | UV_FS_O_CREAT,
                       S_IWUSR | S_IRUSR,
                       NULL);
        ASSERT_GE(r, 0);
        ASSERT_GE(req.result, 0);
        file = req.result;
        uv_fs_req_cleanup(&req);

        r = uv_fs_close(NULL, &req, file, NULL);
        ASSERT_OK(r);
        ASSERT_OK(req.result);
        uv_fs_req_cleanup(&req);

        /* Test */
        r = uv_fs_readlink(NULL, &req, "test_file", NULL);
        ASSERT_EQ(r, UV_EINVAL);
        uv_fs_req_cleanup(&req);

        /* Cleanup */
        unlink("test_file");
    }

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_realpath)
{
    uv_fs_t req;

    loop = uv_default_loop();
    ASSERT_OK(uv_fs_realpath(loop, &req, "no_such_file", dummy_cb));
    ASSERT_OK(uv_run(loop, UV_RUN_DEFAULT));
    ASSERT_EQ(1, dummy_cb_count);
    ASSERT_NULL(req.ptr);
    ASSERT_EQ(req.result, UV_ENOENT);
    uv_fs_req_cleanup(&req);

    ASSERT_EQ(UV_ENOENT, uv_fs_realpath(NULL, &req, "no_such_file", NULL));
    ASSERT_NULL(req.ptr);
    ASSERT_EQ(req.result, UV_ENOENT);
    uv_fs_req_cleanup(&req);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_symlink)
{
    int r;
    uv_fs_t req;
    uv_file file;
    uv_file link;
    char test_file_abs_buf[PATHMAX];
    size_t test_file_abs_size;

    /* Setup. */
    unlink("test_file");
    unlink("test_file_symlink");
    unlink("test_file_symlink2");
    unlink("test_file_symlink_symlink");
    unlink("test_file_symlink2_symlink");
    test_file_abs_size = sizeof(test_file_abs_buf);
    uv_cwd(test_file_abs_buf, &test_file_abs_size);
    strcat(test_file_abs_buf, "/test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &req,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result;
    uv_fs_req_cleanup(&req);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &req, file, &iov, 1, -1, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_EQ(req.result, sizeof(test_buf));
    uv_fs_req_cleanup(&req);

    uv_fs_close(loop, &req, file, NULL);

    /* sync symlink */
    r = uv_fs_symlink(NULL, &req, "test_file", "test_file_symlink", 0, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    r = uv_fs_open(NULL, &req, "test_file_symlink", UV_FS_O_RDWR, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    link = req.result;
    uv_fs_req_cleanup(&req);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &req, link, &iov, 1, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));

    uv_fs_close(loop, &req, link, NULL);

    r = uv_fs_symlink(
        NULL, &req, "test_file_symlink", "test_file_symlink_symlink", 0, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&req);

    r = uv_fs_readlink(NULL, &req, "test_file_symlink_symlink", NULL);
    ASSERT_OK(r);
    ASSERT_OK(strcmp(req.ptr, "test_file_symlink"));
    uv_fs_req_cleanup(&req);

    r = uv_fs_realpath(NULL, &req, "test_file_symlink_symlink", NULL);
    ASSERT_OK(r);
    ASSERT_OK(strcmp(req.ptr, test_file_abs_buf));
    uv_fs_req_cleanup(&req);

    /* async link */
    r = uv_fs_symlink(
        loop, &req, "test_file", "test_file_symlink2", 0, symlink_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, symlink_cb_count);

    r = uv_fs_open(NULL, &req, "test_file_symlink2", UV_FS_O_RDWR, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    link = req.result;
    uv_fs_req_cleanup(&req);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &req, link, &iov, 1, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));

    uv_fs_close(loop, &req, link, NULL);

    r = uv_fs_symlink(NULL,
                      &req,
                      "test_file_symlink2",
                      "test_file_symlink2_symlink",
                      0,
                      NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&req);

    r = uv_fs_readlink(loop, &req, "test_file_symlink2_symlink", readlink_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, readlink_cb_count);

    r = uv_fs_realpath(loop, &req, "test_file", realpath_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, realpath_cb_count);

    /*
     * Run the loop just to check we don't have make any extraneous uv_ref()
     * calls. This should drop out immediately.
     */
    uv_run(loop, UV_RUN_DEFAULT);

    /* Cleanup. */
    unlink("test_file");
    unlink("test_file_symlink");
    unlink("test_file_symlink_symlink");
    unlink("test_file_symlink2");
    unlink("test_file_symlink2_symlink");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


int test_symlink_dir_impl(int type)
{
    uv_fs_t req;
    int r;
    char* test_dir;
    uv_dirent_t dent;
    static char test_dir_abs_buf[PATHMAX];
    size_t test_dir_abs_size;

    /* set-up */
    unlink("test_dir/file1");
    unlink("test_dir/file2");
    rmdir("test_dir");
    rmdir("test_dir_symlink");
    test_dir_abs_size = sizeof(test_dir_abs_buf);

    loop = uv_default_loop();

    uv_fs_mkdir(NULL, &req, "test_dir", 0777, NULL);
    uv_fs_req_cleanup(&req);

    uv_cwd(test_dir_abs_buf, &test_dir_abs_size);
    strcat(test_dir_abs_buf, "/test_dir");
    test_dir_abs_size += strlen("/test_dir");
    test_dir = "test_dir";

    r = uv_fs_symlink(NULL, &req, test_dir, "test_dir_symlink", type, NULL);
    if (type == UV_FS_SYMLINK_DIR && (r == UV_ENOTSUP || r == UV_EPERM)) {
        uv_fs_req_cleanup(&req);
        RETURN_SKIP("this version of Windows doesn't support unprivileged "
                    "creation of directory symlinks");
    }
    fprintf(stderr, "r == %i\n", r);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    r = uv_fs_stat(NULL, &req, "test_dir_symlink", NULL);
    ASSERT_OK(r);
    ASSERT(((uv_stat_t*)req.ptr)->st_mode & S_IFDIR);
    uv_fs_req_cleanup(&req);

    r = uv_fs_lstat(NULL, &req, "test_dir_symlink", NULL);
    ASSERT_OK(r);
    ASSERT(((uv_stat_t*)req.ptr)->st_mode & S_IFLNK);
    ASSERT_EQ(((uv_stat_t*)req.ptr)->st_size, strlen(test_dir));
    uv_fs_req_cleanup(&req);

    r = uv_fs_readlink(NULL, &req, "test_dir_symlink", NULL);
    ASSERT_OK(r);
    ASSERT_OK(strcmp(req.ptr, test_dir));
    uv_fs_req_cleanup(&req);

    r = uv_fs_realpath(NULL, &req, "test_dir_symlink", NULL);
    ASSERT_OK(r);
    ASSERT_OK(strcmp(req.ptr, test_dir_abs_buf));
    uv_fs_req_cleanup(&req);

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_dir/file1",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    uv_fs_req_cleanup(&open_req1);
    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_dir/file2",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    uv_fs_req_cleanup(&open_req1);
    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_scandir(NULL, &scandir_req, "test_dir_symlink", 0, NULL);
    ASSERT_EQ(2, r);
    ASSERT_EQ(2, scandir_req.result);
    ASSERT(scandir_req.ptr);
    while (UV_EOF != uv_fs_scandir_next(&scandir_req, &dent)) {
        ASSERT(strcmp(dent.name, "file1") == 0 ||
               strcmp(dent.name, "file2") == 0);
        assert_is_file_type(dent);
    }
    uv_fs_req_cleanup(&scandir_req);
    ASSERT(!scandir_req.ptr);

    /* unlink will remove the directory symlink */
    r = uv_fs_unlink(NULL, &req, "test_dir_symlink", NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&req);

    r = uv_fs_scandir(NULL, &scandir_req, "test_dir_symlink", 0, NULL);
    ASSERT_EQ(r, UV_ENOENT);
    uv_fs_req_cleanup(&scandir_req);

    r = uv_fs_scandir(NULL, &scandir_req, "test_dir", 0, NULL);
    ASSERT_EQ(2, r);
    ASSERT_EQ(2, scandir_req.result);
    ASSERT(scandir_req.ptr);
    while (UV_EOF != uv_fs_scandir_next(&scandir_req, &dent)) {
        ASSERT(strcmp(dent.name, "file1") == 0 ||
               strcmp(dent.name, "file2") == 0);
        assert_is_file_type(dent);
    }
    uv_fs_req_cleanup(&scandir_req);
    ASSERT(!scandir_req.ptr);

    /* clean-up */
    unlink("test_dir/file1");
    unlink("test_dir/file2");
    rmdir("test_dir");
    rmdir("test_dir_symlink");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_symlink_dir)
{
    return test_symlink_dir_impl(UV_FS_SYMLINK_DIR);
}

TEST_IMPL(fs_symlink_junction)
{
    return test_symlink_dir_impl(UV_FS_SYMLINK_JUNCTION);
}


TEST_IMPL(fs_utime)
{
    utime_check_t checkme;
    const char* path = "test_file";
    double atime;
    double mtime;
    uv_fs_t req;
    int r;

    /* Setup. */
    loop = uv_default_loop();
    unlink(path);
    r = uv_fs_open(NULL,
                   &req,
                   path,
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    uv_fs_req_cleanup(&req);
    uv_fs_close(loop, &req, r, NULL);

    atime = mtime = 400497753.25; /* 1982-09-10 11:22:33.25 */

    r = uv_fs_utime(NULL, &req, path, atime, mtime, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    check_utime(path, atime, mtime, /* test_lutime */ 0);

    atime = mtime = 1291404900.25; /* 2010-12-03 20:35:00.25 - mees <3 */
    checkme.path = path;
    checkme.atime = atime;
    checkme.mtime = mtime;

    /* async utime */
    utime_req.data = &checkme;
    r = uv_fs_utime(loop, &utime_req, path, atime, mtime, utime_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, utime_cb_count);

    /* Cleanup. */
    unlink(path);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_utime_round)
{
    const char path[] = "test_file";
    double atime;
    double mtime;
    uv_fs_t req;
    int r;

    loop = uv_default_loop();
    unlink(path);
    r = uv_fs_open(NULL,
                   &req,
                   path,
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    uv_fs_req_cleanup(&req);
    ASSERT_OK(uv_fs_close(loop, &req, r, NULL));

    atime = mtime = -14245440.25; /* 1969-07-20T02:56:00.25Z */

    r = uv_fs_utime(NULL, &req, path, atime, mtime, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);
    check_utime(path, atime, mtime, /* test_lutime */ 0);
    unlink(path);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_futime)
{
    utime_check_t checkme;
    const char* path = "test_file";
    double atime;
    double mtime;
    uv_file file;
    uv_fs_t req;
    int r;

    /* Setup. */
    loop = uv_default_loop();
    unlink(path);
    r = uv_fs_open(NULL,
                   &req,
                   path,
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    uv_fs_req_cleanup(&req);
    uv_fs_close(loop, &req, r, NULL);

    atime = mtime = 400497753.25; /* 1982-09-10 11:22:33.25 */

    r = uv_fs_open(NULL, &req, path, UV_FS_O_RDWR, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    file = req.result; /* FIXME probably not how it's supposed to be used */
    uv_fs_req_cleanup(&req);

    r = uv_fs_futime(NULL, &req, file, atime, mtime, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    check_utime(path, atime, mtime, /* test_lutime */ 0);

    atime = mtime = 1291404900; /* 2010-12-03 20:35:00 - mees <3 */

    checkme.atime = atime;
    checkme.mtime = mtime;
    checkme.path = path;

    /* async futime */
    futime_req.data = &checkme;
    r = uv_fs_futime(loop, &futime_req, file, atime, mtime, futime_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, futime_cb_count);

    /* Cleanup. */
    unlink(path);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_lutime)
{
    utime_check_t checkme;
    const char* path = "test_file";
    const char* symlink_path = "test_file_symlink";
    double atime;
    double mtime;
    uv_fs_t req;
    int r, s;


    /* Setup */
    loop = uv_default_loop();
    unlink(path);
    r = uv_fs_open(NULL,
                   &req,
                   path,
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    uv_fs_req_cleanup(&req);
    uv_fs_close(loop, &req, r, NULL);

    unlink(symlink_path);
    s = uv_fs_symlink(NULL, &req, path, symlink_path, 0, NULL);
    ASSERT_OK(s);
    ASSERT_OK(req.result);
    uv_fs_req_cleanup(&req);

    /* Test the synchronous version. */
    atime = mtime = 400497753.25; /* 1982-09-10 11:22:33.25 */

    checkme.atime = atime;
    checkme.mtime = mtime;
    checkme.path = symlink_path;
    req.data = &checkme;

    r = uv_fs_lutime(NULL, &req, symlink_path, atime, mtime, NULL);
#if (defined(_AIX) && !defined(_AIX71)) || defined(__MVS__)
    ASSERT_EQ(r, UV_ENOSYS);
    RETURN_SKIP(
        "lutime is not implemented for z/OS and AIX versions below 7.1");
#endif
    ASSERT_OK(r);
    lutime_cb(&req);
    ASSERT_EQ(1, lutime_cb_count);

    /* Test the asynchronous version. */
    atime = mtime = 1291404900; /* 2010-12-03 20:35:00 */

    checkme.atime = atime;
    checkme.mtime = mtime;
    checkme.path = symlink_path;

    r = uv_fs_lutime(loop, &req, symlink_path, atime, mtime, lutime_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(2, lutime_cb_count);

    /* Cleanup. */
    unlink(path);
    unlink(symlink_path);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_stat_missing_path)
{
    uv_fs_t req;
    int r;

    loop = uv_default_loop();

    r = uv_fs_stat(NULL, &req, "non_existent_file", NULL);
    ASSERT_EQ(r, UV_ENOENT);
    ASSERT_EQ(req.result, UV_ENOENT);
    uv_fs_req_cleanup(&req);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_scandir_empty_dir)
{
    const char* path;
    uv_fs_t req;
    uv_dirent_t dent;
    int r;

    path = "./empty_dir/";
    loop = uv_default_loop();

    uv_fs_mkdir(NULL, &req, path, 0777, NULL);
    uv_fs_req_cleanup(&req);

    /* Fill the req to ensure that required fields are cleaned up */
    memset(&req, 0xdb, sizeof(req));

    r = uv_fs_scandir(NULL, &req, path, 0, NULL);
    ASSERT_OK(r);
    ASSERT_OK(req.result);
    ASSERT_NULL(req.ptr);
    ASSERT_EQ(UV_EOF, uv_fs_scandir_next(&req, &dent));
    uv_fs_req_cleanup(&req);

    r = uv_fs_scandir(loop, &scandir_req, path, 0, empty_scandir_cb);
    ASSERT_OK(r);

    ASSERT_OK(scandir_cb_count);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, scandir_cb_count);

    uv_fs_rmdir(NULL, &req, path, NULL);
    uv_fs_req_cleanup(&req);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(fs_scandir_non_existent_dir)
{
    const char* path;
    uv_fs_t req;
    uv_dirent_t dent;
    int r;

    path = "./non_existent_dir/";
    loop = uv_default_loop();

    uv_fs_rmdir(NULL, &req, path, NULL);
    uv_fs_req_cleanup(&req);

    /* Fill the req to ensure that required fields are cleaned up */
    memset(&req, 0xdb, sizeof(req));

    r = uv_fs_scandir(NULL, &req, path, 0, NULL);
    ASSERT_EQ(r, UV_ENOENT);
    ASSERT_EQ(req.result, UV_ENOENT);
    ASSERT_NULL(req.ptr);
    ASSERT_EQ(UV_ENOENT, uv_fs_scandir_next(&req, &dent));
    uv_fs_req_cleanup(&req);

    r = uv_fs_scandir(loop, &scandir_req, path, 0, non_existent_scandir_cb);
    ASSERT_OK(r);

    ASSERT_OK(scandir_cb_count);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, scandir_cb_count);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_scandir_file)
{
    const char* path;
    int r;

    path = "test/fixtures/empty_file";
    loop = uv_default_loop();

    r = uv_fs_scandir(NULL, &scandir_req, path, 0, NULL);
    ASSERT_EQ(r, UV_ENOTDIR);
    uv_fs_req_cleanup(&scandir_req);

    r = uv_fs_scandir(loop, &scandir_req, path, 0, file_scandir_cb);
    ASSERT_OK(r);

    ASSERT_OK(scandir_cb_count);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, scandir_cb_count);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


/* Run in Valgrind. Should not leak when the iterator isn't exhausted. */
TEST_IMPL(fs_scandir_early_exit)
{
    uv_dirent_t d;
    uv_fs_t req;

    ASSERT_LT(0, uv_fs_scandir(NULL, &req, "test/fixtures/one_file", 0, NULL));
    ASSERT_NE(UV_EOF, uv_fs_scandir_next(&req, &d));
    uv_fs_req_cleanup(&req);

    ASSERT_LT(0, uv_fs_scandir(NULL, &req, "test/fixtures", 0, NULL));
    ASSERT_NE(UV_EOF, uv_fs_scandir_next(&req, &d));
    uv_fs_req_cleanup(&req);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


TEST_IMPL(fs_open_dir)
{
    const char* path;
    uv_fs_t req;
    int r, file;

    path = ".";
    loop = uv_default_loop();

    r = uv_fs_open(NULL, &req, path, UV_FS_O_RDONLY, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(req.result, 0);
    ASSERT_NULL(req.ptr);
    file = r;
    uv_fs_req_cleanup(&req);

    r = uv_fs_close(NULL, &req, file, NULL);
    ASSERT_OK(r);

    r = uv_fs_open(loop, &req, path, UV_FS_O_RDONLY, 0, open_cb_simple);
    ASSERT_OK(r);

    ASSERT_OK(open_cb_count);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, open_cb_count);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


static void fs_file_open_append(int add_flags)
{
    int r;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT | add_flags,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(write_req.result, 0);
    uv_fs_req_cleanup(&write_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_APPEND | add_flags,
                   0,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(write_req.result, 0);
    uv_fs_req_cleanup(&write_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_RDONLY | add_flags,
                   S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, -1, NULL);
    printf("read = %d\n", r);
    ASSERT_EQ(26, r);
    ASSERT_EQ(26, read_req.result);
    ASSERT_OK(memcmp(buf,
                     "test-buffer\n\0test-buffer\n\0",
                     sizeof("test-buffer\n\0test-buffer\n\0") - 1));
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    unlink("test_file");
}
TEST_IMPL(fs_file_open_append)
{
    fs_file_open_append(0);
    fs_file_open_append(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


TEST_IMPL(fs_rename_to_existing_file)
{
    int r;

    /* Setup. */
    unlink("test_file");
    unlink("test_file2");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(write_req.result, 0);
    uv_fs_req_cleanup(&write_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file2",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_rename(NULL, &rename_req, "test_file", "test_file2", NULL);
    ASSERT_OK(r);
    ASSERT_OK(rename_req.result);
    uv_fs_req_cleanup(&rename_req);

    r = uv_fs_open(NULL, &open_req1, "test_file2", UV_FS_O_RDONLY, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(read_req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    unlink("test_file");
    unlink("test_file2");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


static void fs_read_bufs(int add_flags)
{
    char scratch[768];
    uv_buf_t bufs[4];

    ASSERT_LE(0,
              uv_fs_open(NULL,
                         &open_req1,
                         "test/fixtures/lorem_ipsum.txt",
                         UV_FS_O_RDONLY | add_flags,
                         0,
                         NULL));
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    ASSERT_EQ(UV_EINVAL,
              uv_fs_read(NULL, &read_req, open_req1.result, NULL, 0, 0, NULL));
    ASSERT_EQ(UV_EINVAL,
              uv_fs_read(NULL, &read_req, open_req1.result, NULL, 1, 0, NULL));
    ASSERT_EQ(UV_EINVAL,
              uv_fs_read(NULL, &read_req, open_req1.result, bufs, 0, 0, NULL));

    bufs[0] = uv_buf_init(scratch + 0, 256);
    bufs[1] = uv_buf_init(scratch + 256, 256);
    bufs[2] = uv_buf_init(scratch + 512, 128);
    bufs[3] = uv_buf_init(scratch + 640, 128);

    ASSERT_EQ(446,
              uv_fs_read(NULL,
                         &read_req,
                         open_req1.result,
                         bufs + 0,
                         2, /* 2x 256 bytes. */
                         0, /* Positional read. */
                         NULL));
    ASSERT_EQ(446, read_req.result);
    uv_fs_req_cleanup(&read_req);

    ASSERT_EQ(190,
              uv_fs_read(NULL,
                         &read_req,
                         open_req1.result,
                         bufs + 2,
                         2,   /* 2x 128 bytes. */
                         256, /* Positional read. */
                         NULL));
    ASSERT_EQ(read_req.result, /* 446 - 256 */ 190);
    uv_fs_req_cleanup(&read_req);

    ASSERT_OK(memcmp(bufs[1].base + 0, bufs[2].base, 128));
    ASSERT_OK(memcmp(bufs[1].base + 128, bufs[3].base, 190 - 128));

    ASSERT_OK(uv_fs_close(NULL, &close_req, open_req1.result, NULL));
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);
}
TEST_IMPL(fs_read_bufs)
{
    fs_read_bufs(0);
    fs_read_bufs(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


static void fs_read_file_eof(int add_flags)
{
    int r;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT | add_flags,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(write_req.result, 0);
    uv_fs_req_cleanup(&write_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(
        NULL, &open_req1, "test_file", UV_FS_O_RDONLY | add_flags, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    memset(buf, 0, sizeof(buf));
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(read_req.result, 0);
    ASSERT_OK(strcmp(buf, test_buf));
    uv_fs_req_cleanup(&read_req);

    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(
        NULL, &read_req, open_req1.result, &iov, 1, read_req.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(read_req.result);
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    unlink("test_file");
}
TEST_IMPL(fs_read_file_eof)
{
    fs_read_file_eof(0);
    fs_read_file_eof(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


static void fs_write_multiple_bufs(int add_flags)
{
    uv_buf_t iovs[2];
    int r;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_WRONLY | UV_FS_O_CREAT | add_flags,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iovs[0] = uv_buf_init(test_buf, sizeof(test_buf));
    iovs[1] = uv_buf_init(test_buf2, sizeof(test_buf2));
    r = uv_fs_write(NULL, &write_req, open_req1.result, iovs, 2, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(write_req.result, 0);
    uv_fs_req_cleanup(&write_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(
        NULL, &open_req1, "test_file", UV_FS_O_RDONLY | add_flags, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    memset(buf, 0, sizeof(buf));
    memset(buf2, 0, sizeof(buf2));
    /* Read the strings back to separate buffers. */
    iovs[0] = uv_buf_init(buf, sizeof(test_buf));
    iovs[1] = uv_buf_init(buf2, sizeof(test_buf2));
    ASSERT_OK(lseek(open_req1.result, 0, SEEK_CUR));
    r = uv_fs_read(NULL, &read_req, open_req1.result, iovs, 2, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_EQ(read_req.result, sizeof(test_buf) + sizeof(test_buf2));
    ASSERT_OK(strcmp(buf, test_buf));
    ASSERT_OK(strcmp(buf2, test_buf2));
    uv_fs_req_cleanup(&read_req);

    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_OK(r);
    ASSERT_OK(read_req.result);
    uv_fs_req_cleanup(&read_req);

    /* Read the strings back to separate buffers. */
    iovs[0] = uv_buf_init(buf, sizeof(test_buf));
    iovs[1] = uv_buf_init(buf2, sizeof(test_buf2));
    r = uv_fs_read(NULL, &read_req, open_req1.result, iovs, 2, 0, NULL);
    ASSERT_GE(r, 0);
    if (read_req.result == sizeof(test_buf)) {
        /* Infer that preadv is not available. */
        uv_fs_req_cleanup(&read_req);
        r = uv_fs_read(NULL,
                       &read_req,
                       open_req1.result,
                       &iovs[1],
                       1,
                       read_req.result,
                       NULL);
        ASSERT_GE(r, 0);
        ASSERT_EQ(read_req.result, sizeof(test_buf2));
    } else {
        ASSERT_EQ(read_req.result, sizeof(test_buf) + sizeof(test_buf2));
    }
    ASSERT_OK(strcmp(buf, test_buf));
    ASSERT_OK(strcmp(buf2, test_buf2));
    uv_fs_req_cleanup(&read_req);

    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL,
                   &read_req,
                   open_req1.result,
                   &iov,
                   1,
                   sizeof(test_buf) + sizeof(test_buf2),
                   NULL);
    ASSERT_OK(r);
    ASSERT_OK(read_req.result);
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    unlink("test_file");
}
TEST_IMPL(fs_write_multiple_bufs)
{
    fs_write_multiple_bufs(0);
    fs_write_multiple_bufs(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


static void fs_write_alotof_bufs(int add_flags)
{
    size_t iovcount;
    size_t iovmax;
    uv_buf_t* iovs;
    char* buffer;
    size_t index;
    int r;

    iovcount = 54321;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    iovs = malloc(sizeof(*iovs) * iovcount);
    ASSERT_NOT_NULL(iovs);
    iovmax = uv_test_getiovmax();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT | add_flags,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    for (index = 0; index < iovcount; ++index)
        iovs[index] = uv_buf_init(test_buf, sizeof(test_buf));

    r = uv_fs_write(
        NULL, &write_req, open_req1.result, iovs, iovcount, -1, NULL);
    ASSERT_GE(r, 0);
    ASSERT_EQ((size_t)write_req.result, sizeof(test_buf) * iovcount);
    uv_fs_req_cleanup(&write_req);

    /* Read the strings back to separate buffers. */
    buffer = malloc(sizeof(test_buf) * iovcount);
    ASSERT_NOT_NULL(buffer);

    for (index = 0; index < iovcount; ++index)
        iovs[index] =
            uv_buf_init(buffer + index * sizeof(test_buf), sizeof(test_buf));

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    r = uv_fs_open(
        NULL, &open_req1, "test_file", UV_FS_O_RDONLY | add_flags, 0, NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    r = uv_fs_read(NULL, &read_req, open_req1.result, iovs, iovcount, -1, NULL);
    if (iovcount > iovmax)
        iovcount = iovmax;
    ASSERT_GE(r, 0);
    ASSERT_EQ((size_t)read_req.result, sizeof(test_buf) * iovcount);

    for (index = 0; index < iovcount; ++index)
        ASSERT_OK(strncmp(
            buffer + index * sizeof(test_buf), test_buf, sizeof(test_buf)));

    uv_fs_req_cleanup(&read_req);
    free(buffer);

    ASSERT_EQ(lseek(open_req1.result, write_req.result, SEEK_SET),
              write_req.result);
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_OK(r);
    ASSERT_OK(read_req.result);
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    unlink("test_file");
    free(iovs);
}
TEST_IMPL(fs_write_alotof_bufs)
{
    fs_write_alotof_bufs(0);
    fs_write_alotof_bufs(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}


static void fs_write_alotof_bufs_with_offset(int add_flags)
{
    size_t iovcount;
    size_t iovmax;
    uv_buf_t* iovs;
    char* buffer;
    size_t index;
    int r;
    int64_t offset;
    char* filler;
    int filler_len;

    filler = "0123456789";
    filler_len = strlen(filler);
    iovcount = 54321;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    iovs = malloc(sizeof(*iovs) * iovcount);
    ASSERT_NOT_NULL(iovs);
    iovmax = uv_test_getiovmax();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT | add_flags,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(filler, filler_len);
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, -1, NULL);
    ASSERT_EQ(r, filler_len);
    ASSERT_EQ(write_req.result, filler_len);
    uv_fs_req_cleanup(&write_req);
    offset = (int64_t)r;

    for (index = 0; index < iovcount; ++index)
        iovs[index] = uv_buf_init(test_buf, sizeof(test_buf));

    r = uv_fs_write(
        NULL, &write_req, open_req1.result, iovs, iovcount, offset, NULL);
    ASSERT_GE(r, 0);
    ASSERT_EQ((size_t)write_req.result, sizeof(test_buf) * iovcount);
    uv_fs_req_cleanup(&write_req);

    /* Read the strings back to separate buffers. */
    buffer = malloc(sizeof(test_buf) * iovcount);
    ASSERT_NOT_NULL(buffer);

    for (index = 0; index < iovcount; ++index)
        iovs[index] =
            uv_buf_init(buffer + index * sizeof(test_buf), sizeof(test_buf));

    r = uv_fs_read(
        NULL, &read_req, open_req1.result, iovs, iovcount, offset, NULL);
    ASSERT_GE(r, 0);
    if (r == sizeof(test_buf))
        iovcount = 1; /* Infer that preadv is not available. */
    else if (iovcount > iovmax)
        iovcount = iovmax;
    ASSERT_EQ((size_t)read_req.result, sizeof(test_buf) * iovcount);

    for (index = 0; index < iovcount; ++index)
        ASSERT_OK(strncmp(
            buffer + index * sizeof(test_buf), test_buf, sizeof(test_buf)));

    uv_fs_req_cleanup(&read_req);
    free(buffer);

    r = uv_fs_stat(NULL, &stat_req, "test_file", NULL);
    ASSERT_OK(r);
    ASSERT_EQ((int64_t)((uv_stat_t*)stat_req.ptr)->st_size,
              offset + (int64_t)write_req.result);
    uv_fs_req_cleanup(&stat_req);

    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL,
                   &read_req,
                   open_req1.result,
                   &iov,
                   1,
                   offset + write_req.result,
                   NULL);
    ASSERT_OK(r);
    ASSERT_OK(read_req.result);
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    unlink("test_file");
    free(iovs);
}
TEST_IMPL(fs_write_alotof_bufs_with_offset)
{
    fs_write_alotof_bufs_with_offset(0);
    fs_write_alotof_bufs_with_offset(UV_FS_O_FILEMAP);

    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}

TEST_IMPL(fs_read_dir)
{
    int r;
    char buf[2];
    loop = uv_default_loop();

    /* Setup */
    rmdir("test_dir");
    r = uv_fs_mkdir(loop, &mkdir_req, "test_dir", 0755, mkdir_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(1, mkdir_cb_count);
    /* Setup Done Here */

    /* Get a file descriptor for the directory */
    r = uv_fs_open(loop,
                   &open_req1,
                   "test_dir",
                   UV_FS_O_RDONLY | UV_FS_O_DIRECTORY,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    uv_fs_req_cleanup(&open_req1);

    /* Try to read data from the directory */
    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, 0, NULL);
    ASSERT_EQ(r, UV_EISDIR);
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    rmdir("test_dir");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

struct thread_ctx
{
    pthread_t pid;
    int fd;
    char* data;
    int size;
    int interval;
    int doread;
};

static void thread_main(void* arg)
{
    const struct thread_ctx* ctx;
    int size;
    char* data;

    ctx = (struct thread_ctx*)arg;
    size = ctx->size;
    data = ctx->data;

    while (size > 0) {
        ssize_t result;
        int nbytes;
        nbytes = size < ctx->interval ? size : ctx->interval;
        if (ctx->doread) {
            result = write(ctx->fd, data, nbytes);
            /* Should not see EINTR (or other errors) */
            ASSERT_EQ(result, nbytes);
        } else {
            result = read(ctx->fd, data, nbytes);
            /* Should not see EINTR (or other errors),
             * but might get a partial read if we are faster than the writer
             */
            ASSERT(result > 0 && result <= nbytes);
        }

        pthread_kill(ctx->pid, SIGUSR1);
        size -= result;
        data += result;
    }
}

static void sig_func(uv_signal_t* handle, int signum)
{
    uv_signal_stop(handle);
}

static size_t uv_test_fs_buf_offset(uv_buf_t* bufs, size_t size)
{
    size_t offset;
    /* Figure out which bufs are done */
    for (offset = 0; size > 0 && bufs[offset].len <= size; ++offset)
        size -= bufs[offset].len;

    /* Fix a partial read/write */
    if (size > 0) {
        bufs[offset].base += size;
        bufs[offset].len -= size;
    }
    return offset;
}

static void test_fs_partial(int doread)
{
    struct thread_ctx ctx;
    uv_thread_t thread;
    uv_signal_t signal;
    int pipe_fds[2];
    size_t iovcount;
    uv_buf_t* iovs;
    char* buffer;
    size_t index;

    iovcount = 54321;

    iovs = malloc(sizeof(*iovs) * iovcount);
    ASSERT_NOT_NULL(iovs);

    ctx.pid = pthread_self();
    ctx.doread = doread;
    ctx.interval = 1000;
    ctx.size = sizeof(test_buf) * iovcount;
    ctx.data = calloc(ctx.size, 1);
    ASSERT_NOT_NULL(ctx.data);
    buffer = calloc(ctx.size, 1);
    ASSERT_NOT_NULL(buffer);

    for (index = 0; index < iovcount; ++index)
        iovs[index] =
            uv_buf_init(buffer + index * sizeof(test_buf), sizeof(test_buf));

    loop = uv_default_loop();

    ASSERT_OK(uv_signal_init(loop, &signal));
    ASSERT_OK(uv_signal_start(&signal, sig_func, SIGUSR1));

    ASSERT_OK(pipe(pipe_fds));

    ctx.fd = pipe_fds[doread];
    ASSERT_OK(uv_thread_create(&thread, thread_main, &ctx));

    if (doread) {
        uv_buf_t* read_iovs;
        int nread;
        read_iovs = iovs;
        nread = 0;
        while (nread < ctx.size) {
            int result;
            result = uv_fs_read(
                loop, &read_req, pipe_fds[0], read_iovs, iovcount, -1, NULL);
            if (result > 0) {
                size_t read_iovcount;
                read_iovcount = uv_test_fs_buf_offset(read_iovs, result);
                read_iovs += read_iovcount;
                iovcount -= read_iovcount;
                nread += result;
            } else {
                ASSERT_EQ(result, UV_EINTR);
            }
            uv_fs_req_cleanup(&read_req);
        }
    } else {
        int result;
        result = uv_fs_write(
            loop, &write_req, pipe_fds[1], iovs, iovcount, -1, NULL);
        ASSERT_EQ(write_req.result, result);
        ASSERT_EQ(result, ctx.size);
        uv_fs_req_cleanup(&write_req);
    }

    ASSERT_OK(uv_thread_join(&thread));

    ASSERT_MEM_EQ(buffer, ctx.data, ctx.size);

    ASSERT_OK(uv_run(loop, UV_RUN_DEFAULT));

    ASSERT_OK(close(pipe_fds[1]));
    uv_close((uv_handle_t*)&signal, NULL);

    { /* Make sure we read everything that we wrote. */
        int result;
        result = uv_fs_read(loop, &read_req, pipe_fds[0], iovs, 1, -1, NULL);
        ASSERT_OK(result);
        uv_fs_req_cleanup(&read_req);
    }
    ASSERT_OK(close(pipe_fds[0]));

    free(iovs);
    free(buffer);
    free(ctx.data);

    MAKE_VALGRIND_HAPPY(loop);
}

TEST_IMPL(fs_partial_read)
{
    test_fs_partial(1);
    return 0;
}

TEST_IMPL(fs_partial_write)
{
    test_fs_partial(0);
    return 0;
}

TEST_IMPL(fs_read_write_null_arguments)
{
    int r;

    r = uv_fs_read(NULL, &read_req, 0, NULL, 0, -1, NULL);
    ASSERT_EQ(r, UV_EINVAL);
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_write(NULL, &write_req, 0, NULL, 0, -1, NULL);
    /* Validate some memory management on failed input validation before sending
       fs work to the thread pool. */
    ASSERT_EQ(r, UV_EINVAL);
    ASSERT_NULL(write_req.path);
    ASSERT_NULL(write_req.ptr);
    ASSERT_NULL(write_req.new_path);
    ASSERT_NULL(write_req.bufs);
    uv_fs_req_cleanup(&write_req);

    iov = uv_buf_init(NULL, 0);
    r = uv_fs_read(NULL, &read_req, 0, &iov, 0, -1, NULL);
    ASSERT_EQ(r, UV_EINVAL);
    uv_fs_req_cleanup(&read_req);

    iov = uv_buf_init(NULL, 0);
    r = uv_fs_write(NULL, &write_req, 0, &iov, 0, -1, NULL);
    ASSERT_EQ(r, UV_EINVAL);
    uv_fs_req_cleanup(&write_req);

    /* If the arguments are invalid, the loop should not be kept open */
    loop = uv_default_loop();

    r = uv_fs_read(loop, &read_req, 0, NULL, 0, -1, fail_cb);
    ASSERT_EQ(r, UV_EINVAL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_write(loop, &write_req, 0, NULL, 0, -1, fail_cb);
    ASSERT_EQ(r, UV_EINVAL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_fs_req_cleanup(&write_req);

    iov = uv_buf_init(NULL, 0);
    r = uv_fs_read(loop, &read_req, 0, &iov, 0, -1, fail_cb);
    ASSERT_EQ(r, UV_EINVAL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_fs_req_cleanup(&read_req);

    iov = uv_buf_init(NULL, 0);
    r = uv_fs_write(loop, &write_req, 0, &iov, 0, -1, fail_cb);
    ASSERT_EQ(r, UV_EINVAL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_fs_req_cleanup(&write_req);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(get_osfhandle_valid_handle)
{
    int r;
    uv_os_fd_t fd;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    fd = uv_get_osfhandle(open_req1.result);
    ASSERT_GE(fd, 0);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup. */
    unlink("test_file");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(open_osfhandle_valid_handle)
{
    int r;
    uv_os_fd_t handle;
    int fd;

    /* Setup. */
    unlink("test_file");

    loop = uv_default_loop();

    r = uv_fs_open(NULL,
                   &open_req1,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GE(r, 0);
    ASSERT_GE(open_req1.result, 0);
    uv_fs_req_cleanup(&open_req1);

    handle = uv_get_osfhandle(open_req1.result);
    ASSERT_GE(handle, 0);

    fd = uv_open_osfhandle(handle);
    ASSERT_EQ(fd, open_req1.result);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    ASSERT_OK(close_req.result);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup. */
    unlink("test_file");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_file_pos_after_op_with_offset)
{
    int r;

    /* Setup. */
    unlink("test_file");
    loop = uv_default_loop();

    r = uv_fs_open(loop,
                   &open_req1,
                   "test_file",
                   UV_FS_O_RDWR | UV_FS_O_CREAT,
                   S_IWUSR | S_IRUSR,
                   NULL);
    ASSERT_GT(r, 0);
    uv_fs_req_cleanup(&open_req1);

    iov = uv_buf_init(test_buf, sizeof(test_buf));
    r = uv_fs_write(NULL, &write_req, open_req1.result, &iov, 1, 0, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_OK(lseek(open_req1.result, 0, SEEK_CUR));
    uv_fs_req_cleanup(&write_req);

    iov = uv_buf_init(buf, sizeof(buf));
    r = uv_fs_read(NULL, &read_req, open_req1.result, &iov, 1, 0, NULL);
    ASSERT_EQ(r, sizeof(test_buf));
    ASSERT_OK(strcmp(buf, test_buf));
    ASSERT_OK(lseek(open_req1.result, 0, SEEK_CUR));
    uv_fs_req_cleanup(&read_req);

    r = uv_fs_close(NULL, &close_req, open_req1.result, NULL);
    ASSERT_OK(r);
    uv_fs_req_cleanup(&close_req);

    /* Cleanup */
    unlink("test_file");

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_null_req)
{
    /* Verify that all fs functions return UV_EINVAL when the request is NULL.
     */
    int r;

    r = uv_fs_open(NULL, NULL, NULL, 0, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_close(NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_read(NULL, NULL, 0, NULL, 0, -1, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_write(NULL, NULL, 0, NULL, 0, -1, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_unlink(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_mkdir(NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_mkdtemp(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_mkstemp(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_rmdir(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_scandir(NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_link(NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_symlink(NULL, NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_readlink(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_realpath(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_chown(NULL, NULL, NULL, 0, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_fchown(NULL, NULL, 0, 0, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_stat(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_lstat(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_fstat(NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_rename(NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_fsync(NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_fdatasync(NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_ftruncate(NULL, NULL, 0, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_copyfile(NULL, NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_sendfile(NULL, NULL, 0, 0, 0, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_access(NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_chmod(NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_fchmod(NULL, NULL, 0, 0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_utime(NULL, NULL, NULL, 0.0, 0.0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_futime(NULL, NULL, 0, 0.0, 0.0, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    r = uv_fs_statfs(NULL, NULL, NULL, NULL);
    ASSERT_EQ(r, UV_EINVAL);

    /* This should be a no-op. */
    uv_fs_req_cleanup(NULL);

    return 0;
}

TEST_IMPL(fs_statfs)
{
    uv_fs_t req;
    int r;

    loop = uv_default_loop();

    /* Test the synchronous version. */
    r = uv_fs_statfs(NULL, &req, ".", NULL);
    ASSERT_OK(r);
    statfs_cb(&req);
    ASSERT_EQ(1, statfs_cb_count);

    /* Test the asynchronous version. */
    r = uv_fs_statfs(loop, &req, ".", statfs_cb);
    ASSERT_OK(r);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(2, statfs_cb_count);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}

TEST_IMPL(fs_get_system_error)
{
    uv_fs_t req;
    int r;
    int system_error;

    r = uv_fs_statfs(NULL, &req, "non_existing_file", NULL);
    ASSERT(r);

    system_error = uv_fs_get_system_error(&req);
    ASSERT_EQ(system_error, ENOENT);

    return 0;
}


TEST_IMPL(fs_stat_batch_multiple)
{
    uv_fs_t req[300];
    int r;
    int i;

    rmdir("test_dir");

    r = uv_fs_mkdir(NULL, &mkdir_req, "test_dir", 0755, NULL);
    ASSERT_OK(r);

    loop = uv_default_loop();

    for (i = 0; i < (int)ARRAY_SIZE(req); ++i) {
        r = uv_fs_stat(loop, &req[i], "test_dir", stat_batch_cb);
        ASSERT_OK(r);
    }

    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_EQ(stat_cb_count, ARRAY_SIZE(req));

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}
