cmake_minimum_required(VERSION 3.9)

project(libuv LANGUAGES C)

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckCCompilerFlag)
include(GNUInstallDirs)
include(CTest)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD 90)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(LIBUV_BUILD_SHARED "Build shared lib" ON)

cmake_dependent_option(LIBUV_BUILD_TESTS
    "Build the unit tests when BUILD_TESTING is enabled and we are the root project" ON
    "BUILD_TESTING;LIBUV_BUILD_SHARED;CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR" OFF)
cmake_dependent_option(LIBUV_BUILD_BENCH
    "Build the benchmarks when building unit tests and we are the root project" ON
    "LIBUV_BUILD_TESTS" OFF)

# Note: these are mutually exclusive.
option(ASAN "Enable AddressSanitizer (ASan)" OFF)
option(MSAN "Enable MemorySanitizer (MSan)" OFF)
option(TSAN "Enable ThreadSanitizer (TSan)" OFF)
option(UBSAN "Enable UndefinedBehaviorSanitizer (UBSan)" OFF)

if(MSAN AND NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(SEND_ERROR "MemorySanitizer requires clang. Try again with -DCMAKE_C_COMPILER=clang")
endif()

if(ASAN)
    list(APPEND uv_defines __ASAN__=1)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address")
        set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=address")
        set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=address")
    else()
        message(SEND_ERROR "AddressSanitizer support requires clang, gcc, or msvc. Try again with -DCMAKE_C_COMPILER.")
    endif()
endif()

if(MSAN)
    list(APPEND uv_defines __MSAN__=1)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=memory")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=memory")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=memory")
endif()

if(TSAN)
    list(APPEND uv_defines __TSAN__=1)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=thread")
        set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=thread")
        set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=thread")
    else()
        message(SEND_ERROR "ThreadSanitizer support requires clang or gcc. Try again with -DCMAKE_C_COMPILER.")
    endif()
endif()

if(UBSAN)
    list(APPEND uv_defines __UBSAN__=1)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=undefined")
        set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=undefined")
        set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=undefined")
    else()
        message(SEND_ERROR "UndefinedBehaviorSanitizer support requires clang, gcc, or msvc. Try again with -DCMAKE_C_COMPILER.")
    endif()
endif()

# Compiler check
check_c_compiler_flag(-Wall UV_LINT_WALL) # DO NOT use this under MSVC
check_c_compiler_flag(-Wno-unused-parameter UV_LINT_NO_UNUSED_PARAMETER)
check_c_compiler_flag(-Wstrict-prototypes UV_LINT_STRICT_PROTOTYPES)
check_c_compiler_flag(-Wextra UV_LINT_EXTRA)
check_c_compiler_flag(-fno-strict-aliasing UV_F_STRICT_ALIASING)

set(lint-no-unused-parameter $<$<BOOL:${UV_LINT_NO_UNUSED_PARAMETER}>:-Wno-unused-parameter>)
set(lint-strict-prototypes $<$<BOOL:${UV_LINT_STRICT_PROTOTYPES}>:-Wstrict-prototypes>)
set(lint-extra $<$<BOOL:${UV_LINT_EXTRA}>:-Wextra>)
set(lint-wall $<$<BOOL:${UV_LINT_WALL}>:-Wall>)
set(lint-no-strict-aliasing $<$<BOOL:${UV_F_STRICT_ALIASING}>:-fno-strict-aliasing>)

list(APPEND uv_cflags ${lint-strict-prototypes} ${lint-extra} ${lint-wall}
    ${lint-no-unused-parameter} ${lint-no-strict-aliasing})

set(uv_sources
    src/fs-poll.c
    src/idna.c
    src/inet.c
    src/random.c
    src/strscpy.c
    src/strtok.c
    src/thread-common.c
    src/threadpool.c
    src/timer.c
    src/uv-common.c
    src/uv-data-getter-setters.c
    src/version.c)

list(APPEND uv_defines _FILE_OFFSET_BITS=64 _LARGEFILE_SOURCE)
# TODO: This should be replaced with find_package(Threads) if possible
# Android has pthread as part of its c library, not as a separate
# libpthread.so.
list(APPEND uv_libraries pthread)
list(APPEND uv_sources
    src/unix/async.c
    src/unix/core.c
    src/unix/dl.c
    src/unix/fs.c
    src/unix/getaddrinfo.c
    src/unix/getnameinfo.c
    src/unix/loop-watcher.c
    src/unix/loop.c
    src/unix/pipe.c
    src/unix/poll.c
    src/unix/process.c
    src/unix/random-devurandom.c
    src/unix/signal.c
    src/unix/stream.c
    src/unix/tcp.c
    src/unix/thread.c
    src/unix/tty.c
    src/unix/udp.c)
list(APPEND uv_test_sources test/runner-unix.c)

list(APPEND uv_sources src/unix/proctitle.c)
list(APPEND uv_defines _GNU_SOURCE _POSIX_C_SOURCE=200112)
list(APPEND uv_libraries dl rt)
list(APPEND uv_sources
    src/unix/linux.c
    src/unix/procfs-exepath.c
    src/unix/random-getrandom.c
    src/unix/random-sysctl-linux.c)
list(APPEND uv_test_libraries util)

if(LIBUV_BUILD_SHARED)
    add_library(uv SHARED ${uv_sources})
    target_compile_definitions(uv
        INTERFACE
        USING_UV_SHARED=1
        PRIVATE
        BUILDING_UV_SHARED=1
        ${uv_defines})
    target_compile_options(uv PRIVATE ${uv_cflags})
    target_include_directories(uv
        PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)
    if(CMAKE_SYSTEM_NAME STREQUAL "OS390")
        target_include_directories(uv PUBLIC $<BUILD_INTERFACE:${ZOSLIB_DIR}/include>)
        set_target_properties(uv PROPERTIES LINKER_LANGUAGE CXX)
    endif()
    target_link_libraries(uv ${uv_libraries})
    set_target_properties(uv PROPERTIES OUTPUT_NAME "uv")
endif()

add_library(uv_a STATIC ${uv_sources})
target_compile_definitions(uv_a PRIVATE ${uv_defines})
target_compile_options(uv_a PRIVATE ${uv_cflags})
target_include_directories(uv_a
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)
target_link_libraries(uv_a ${uv_libraries})
set_target_properties(uv_a PROPERTIES OUTPUT_NAME "uv")

if(LIBUV_BUILD_TESTS)
    # Small hack: use ${uv_test_sources} now to get the runner skeleton,
    # before the actual tests are added.
    add_executable(
        uv_run_benchmarks_a
        ${uv_test_sources}
        test/benchmark-async-pummel.c
        test/benchmark-async.c
        test/benchmark-fs-stat.c
        test/benchmark-getaddrinfo.c
        test/benchmark-loop-count.c
        test/benchmark-queue-work.c
        test/benchmark-million-async.c
        test/benchmark-million-timers.c
        test/benchmark-multi-accept.c
        test/benchmark-ping-pongs.c
        test/benchmark-ping-udp.c
        test/benchmark-pound.c
        test/benchmark-pump.c
        test/benchmark-sizes.c
        test/benchmark-spawn.c
        test/benchmark-tcp-write-batch.c
        test/benchmark-thread.c
        test/benchmark-udp-pummel.c
        test/blackhole-server.c
        test/echo-server.c
        test/run-benchmarks.c
        test/runner.c)
    target_compile_definitions(uv_run_benchmarks_a PRIVATE ${uv_defines})
    target_compile_options(uv_run_benchmarks_a PRIVATE ${uv_cflags})
    target_link_libraries(uv_run_benchmarks_a uv_a ${uv_test_libraries})

    list(APPEND uv_test_sources
        test/blackhole-server.c
        test/echo-server.c
        test/run-tests.c
        test/runner.c
        test/test-active.c
        test/test-async-null-cb.c
        test/test-async.c
        test/test-barrier.c
        test/test-callback-stack.c
        test/test-close-fd.c
        test/test-close-order.c
        test/test-condvar.c
        test/test-connect-unspecified.c
        test/test-connection-fail.c
        test/test-cwd-and-chdir.c
        test/test-default-loop-close.c
        test/test-delayed-accept.c
        test/test-dlerror.c
        test/test-eintr-handling.c
        test/test-embed.c
        test/test-emfile.c
        test/test-env-vars.c
        test/test-error.c
        test/test-fail-always.c
        test/test-fork.c
        test/test-fs-copyfile.c
        test/test-fs-event.c
        test/test-fs-poll.c
        test/test-fs.c
        test/test-fs-readdir.c
        test/test-fs-fd-hash.c
        test/test-fs-open-flags.c
        test/test-get-currentexe.c
        test/test-get-loadavg.c
        test/test-get-memory.c
        test/test-get-passwd.c
        test/test-getaddrinfo.c
        test/test-gethostname.c
        test/test-getnameinfo.c
        test/test-getsockname.c
        test/test-getters-setters.c
        test/test-gettimeofday.c
        test/test-handle-fileno.c
        test/test-homedir.c
        test/test-hrtime.c
        test/test-idle.c
        test/test-idna.c
        test/test-iouring-pollhup.c
        test/test-ip4-addr.c
        test/test-ip6-addr.c
        test/test-ip-name.c
        test/test-ipc-heavy-traffic-deadlock-bug.c
        test/test-ipc-send-recv.c
        test/test-ipc.c
        test/test-loop-alive.c
        test/test-loop-close.c
        test/test-loop-configure.c
        test/test-loop-handles.c
        test/test-loop-stop.c
        test/test-loop-time.c
        test/test-metrics.c
        test/test-multiple-listen.c
        test/test-mutexes.c
        test/test-not-readable-nor-writable-on-read-error.c
        test/test-not-writable-after-shutdown.c
        test/test-osx-select.c
        test/test-pass-always.c
        test/test-ping-pong.c
        test/test-pipe-bind-error.c
        test/test-pipe-close-stdout-read-stdin.c
        test/test-pipe-connect-error.c
        test/test-pipe-connect-multiple.c
        test/test-pipe-connect-prepare.c
        test/test-pipe-getsockname.c
        test/test-pipe-pending-instances.c
        test/test-pipe-sendmsg.c
        test/test-pipe-server-close.c
        test/test-pipe-set-fchmod.c
        test/test-pipe-set-non-blocking.c
        test/test-platform-output.c
        test/test-poll-close-doesnt-corrupt-stack.c
        test/test-poll-close.c
        test/test-poll-closesocket.c
        test/test-poll-multiple-handles.c
        test/test-poll-oob.c
        test/test-poll.c
        test/test-process-priority.c
        test/test-process-title-threadsafe.c
        test/test-process-title.c
        test/test-queue-foreach-delete.c
        test/test-random.c
        test/test-readable-on-eof.c
        test/test-ref.c
        test/test-run-nowait.c
        test/test-run-once.c
        test/test-semaphore.c
        test/test-shutdown-close.c
        test/test-shutdown-eof.c
        test/test-shutdown-simultaneous.c
        test/test-shutdown-twice.c
        test/test-signal-multiple-loops.c
        test/test-signal-pending-on-close.c
        test/test-signal.c
        test/test-socket-buffer-size.c
        test/test-spawn.c
        test/test-stdio-over-pipes.c
        test/test-strscpy.c
        test/test-strtok.c
        test/test-tcp-alloc-cb-fail.c
        test/test-tcp-bind-error.c
        test/test-tcp-bind6-error.c
        test/test-tcp-close-accept.c
        test/test-tcp-close-after-read-timeout.c
        test/test-tcp-close-while-connecting.c
        test/test-tcp-close.c
        test/test-tcp-close-reset.c
        test/test-tcp-connect-error-after-write.c
        test/test-tcp-connect-error.c
        test/test-tcp-connect-timeout.c
        test/test-tcp-connect6-error.c
        test/test-tcp-create-socket-early.c
        test/test-tcp-flags.c
        test/test-tcp-oob.c
        test/test-tcp-open.c
        test/test-tcp-read-stop.c
        test/test-tcp-read-stop-start.c
        test/test-tcp-rst.c
        test/test-tcp-shutdown-after-write.c
        test/test-tcp-try-write.c
        test/test-tcp-write-in-a-row.c
        test/test-tcp-try-write-error.c
        test/test-tcp-unexpected-read.c
        test/test-tcp-write-after-connect.c
        test/test-tcp-write-fail.c
        test/test-tcp-write-queue-order.c
        test/test-tcp-write-to-half-open-connection.c
        test/test-tcp-writealot.c
        test/test-test-macros.c
        test/test-thread-affinity.c
        test/test-thread-equal.c
        test/test-thread.c
        test/test-thread-priority.c
        test/test-threadpool-cancel.c
        test/test-threadpool.c
        test/test-timer-again.c
        test/test-timer-from-check.c
        test/test-timer.c
        test/test-tmpdir.c
        test/test-tty-duplicate-key.c
        test/test-tty-escape-sequence-processing.c
        test/test-tty.c
        test/test-udp-alloc-cb-fail.c
        test/test-udp-bind.c
        test/test-udp-connect.c
        test/test-udp-connect6.c
        test/test-udp-create-socket-early.c
        test/test-udp-dgram-too-big.c
        test/test-udp-ipv6.c
        test/test-udp-mmsg.c
        test/test-udp-multicast-interface.c
        test/test-udp-multicast-interface6.c
        test/test-udp-multicast-join.c
        test/test-udp-multicast-join6.c
        test/test-udp-multicast-ttl.c
        test/test-udp-open.c
        test/test-udp-options.c
        test/test-udp-send-and-recv.c
        test/test-udp-send-hang-loop.c
        test/test-udp-send-immediate.c
        test/test-udp-sendmmsg-error.c
        test/test-udp-send-unreachable.c
        test/test-udp-try-send.c
        test/test-udp-recv-in-a-row.c
        test/test-uname.c
        test/test-walk-handles.c
        test/test-watcher-cross-stop.c)

    add_executable(uv_run_tests ${uv_test_sources} uv_win_longpath.manifest)
    target_compile_definitions(uv_run_tests
        PRIVATE ${uv_defines} USING_UV_SHARED=1)
    target_compile_options(uv_run_tests PRIVATE ${uv_cflags})
    target_link_libraries(uv_run_tests uv ${uv_test_libraries})
    add_test(NAME uv_test
        COMMAND uv_run_tests
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_executable(uv_run_tests_a ${uv_test_sources} uv_win_longpath.manifest)
    target_compile_definitions(uv_run_tests_a PRIVATE ${uv_defines})
    target_compile_options(uv_run_tests_a PRIVATE ${uv_cflags})
    if(QEMU)
        target_link_libraries(uv_run_tests_a uv_a ${uv_test_libraries} -static)
    else()
        target_link_libraries(uv_run_tests_a uv_a ${uv_test_libraries})
    endif()
    add_test(NAME uv_test_a
        COMMAND uv_run_tests_a
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# Now for some gibbering horrors from beyond the stars...
foreach(lib IN LISTS uv_libraries)
    list(APPEND LIBS "-l${lib}")
endforeach()
string(REPLACE ";" " " LIBS "${LIBS}")
# Consider setting project version via project() call?
file(STRINGS configure.ac configure_ac REGEX ^AC_INIT)
string(REGEX MATCH "([0-9]+)[.][0-9]+[.][0-9]+" PACKAGE_VERSION "${configure_ac}")
set(UV_VERSION_MAJOR "${CMAKE_MATCH_1}")

set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(prefix ${CMAKE_INSTALL_PREFIX})
configure_file(libuv-static.pc.in libuv-static.pc @ONLY)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES LICENSE-extra DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES ${PROJECT_BINARY_DIR}/libuv-static.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(TARGETS uv_a EXPORT libuvConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(EXPORT libuvConfig
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libuv
    NAMESPACE libuv::)

if(LIBUV_BUILD_SHARED)
    # The version in the filename is mirroring the behaviour of autotools.
    set_target_properties(uv PROPERTIES
        VERSION ${UV_VERSION_MAJOR}.0.0
        SOVERSION ${UV_VERSION_MAJOR})
    configure_file(libuv.pc.in libuv.pc @ONLY)
    install(FILES ${PROJECT_BINARY_DIR}/libuv.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    install(TARGETS uv EXPORT libuvConfig
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

if(BUILD_SHARED_LIBS)
    set(LIB_SELECTED uv)
else()
    set(LIB_SELECTED uv_a)
endif()

add_library(libuv::libuv ALIAS ${LIB_SELECTED})

message(STATUS "summary of build options:
Install prefix:  ${CMAKE_INSTALL_PREFIX}
Target system:   ${CMAKE_SYSTEM_NAME}
Compiler:
C compiler:    ${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID})
CFLAGS:        ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
")
