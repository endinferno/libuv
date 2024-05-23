cmake_minimum_required(VERSION 3.9)

project(libuv LANGUAGES CXX)

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)
include(GNUInstallDirs)
include(CTest)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_COMPILER "g++-10")
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
check_cxx_compiler_flag(-Wall UV_LINT_WALL) # DO NOT use this under MSVC
check_cxx_compiler_flag(-Wno-unused-parameter UV_LINT_NO_UNUSED_PARAMETER)
check_cxx_compiler_flag(-Wstrict-prototypes UV_LINT_STRICT_PROTOTYPES)
check_cxx_compiler_flag(-Wextra UV_LINT_EXTRA)
check_cxx_compiler_flag(-fno-strict-aliasing UV_F_STRICT_ALIASING)

set(lint-no-unused-parameter $<$<BOOL:${UV_LINT_NO_UNUSED_PARAMETER}>:-Wno-unused-parameter>)
set(lint-strict-prototypes $<$<BOOL:${UV_LINT_STRICT_PROTOTYPES}>:-Wstrict-prototypes>)
set(lint-extra $<$<BOOL:${UV_LINT_EXTRA}>:-Wextra>)
set(lint-wall $<$<BOOL:${UV_LINT_WALL}>:-Wall>)
set(lint-no-strict-aliasing $<$<BOOL:${UV_F_STRICT_ALIASING}>:-fno-strict-aliasing>)

list(APPEND uv_cflags ${lint-strict-prototypes} ${lint-extra} ${lint-wall}
    ${lint-no-unused-parameter} ${lint-no-strict-aliasing})

set(uv_sources
    src/fs-poll.cpp
    src/idna.cpp
    src/inet.cpp
    src/random.cpp
    src/strscpy.cpp
    src/strtok.cpp
    src/thread-common.cpp
    src/threadpool.cpp
    src/timer.cpp
    src/uv-common.cpp
    src/uv-data-getter-setters.cpp
    src/version.cpp)

list(APPEND uv_defines _FILE_OFFSET_BITS=64 _LARGEFILE_SOURCE)
# TODO: This should be replaced with find_package(Threads) if possible
# Android has pthread as part of its c library, not as a separate
# libpthread.so.
list(APPEND uv_libraries pthread)
list(APPEND uv_sources
    src/unix/async.cpp
    src/unix/core.cpp
    src/unix/dl.cpp
    src/unix/fs.cpp
    src/unix/getaddrinfo.cpp
    src/unix/getnameinfo.cpp
    src/unix/loop-watcher.cpp
    src/unix/loop.cpp
    src/unix/pipe.cpp
    src/unix/poll.cpp
    src/unix/process.cpp
    src/unix/random-devurandom.cpp
    src/unix/signal.cpp
    src/unix/stream.cpp
    src/unix/tcp.cpp
    src/unix/thread.cpp
    src/unix/tty.cpp
    src/unix/udp.cpp)
list(APPEND uv_test_sources test/runner-unix.cpp)

list(APPEND uv_sources src/unix/proctitle.cpp)
list(APPEND uv_defines _GNU_SOURCE _POSIX_C_SOURCE=200112)
list(APPEND uv_libraries dl rt)
list(APPEND uv_sources
    src/unix/linux.cpp
    src/unix/procfs-exepath.cpp
    src/unix/random-getrandom.cpp
    src/unix/random-sysctl-linux.cpp)
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
        test/benchmark-async-pummel.cpp
        test/benchmark-async.cpp
        test/benchmark-fs-stat.cpp
        test/benchmark-getaddrinfo.cpp
        test/benchmark-loop-count.cpp
        test/benchmark-queue-work.cpp
        test/benchmark-million-async.cpp
        test/benchmark-million-timers.cpp
        test/benchmark-multi-accept.cpp
        test/benchmark-ping-pongs.cpp
        test/benchmark-ping-udp.cpp
        test/benchmark-pound.cpp
        test/benchmark-pump.cpp
        test/benchmark-sizes.cpp
        test/benchmark-spawn.cpp
        test/benchmark-tcp-write-batch.cpp
        test/benchmark-thread.cpp
        test/benchmark-udp-pummel.cpp
        test/blackhole-server.cpp
        test/echo-server.cpp
        test/run-benchmarks.cpp
        test/runner.cpp)
    target_compile_definitions(uv_run_benchmarks_a PRIVATE ${uv_defines})
    target_compile_options(uv_run_benchmarks_a PRIVATE ${uv_cflags})
    target_link_libraries(uv_run_benchmarks_a uv_a ${uv_test_libraries})

    list(APPEND uv_test_sources
        test/blackhole-server.cpp
        test/echo-server.cpp
        test/run-tests.cpp
        test/runner.cpp
        test/test-active.cpp
        test/test-async-null-cb.cpp
        test/test-async.cpp
        test/test-barrier.cpp
        test/test-callback-stack.cpp
        test/test-close-fd.cpp
        test/test-close-order.cpp
        test/test-condvar.cpp
        test/test-connect-unspecified.cpp
        test/test-connection-fail.cpp
        test/test-cwd-and-chdir.cpp
        test/test-default-loop-close.cpp
        test/test-delayed-accept.cpp
        test/test-dlerror.cpp
        test/test-eintr-handling.cpp
        test/test-embed.cpp
        test/test-emfile.cpp
        test/test-env-vars.cpp
        test/test-error.cpp
        test/test-fail-always.cpp
        test/test-fork.cpp
        test/test-fs-copyfile.cpp
        test/test-fs-event.cpp
        test/test-fs-poll.cpp
        test/test-fs.cpp
        test/test-fs-readdir.cpp
        test/test-fs-fd-hash.cpp
        test/test-fs-open-flags.cpp
        test/test-get-currentexe.cpp
        test/test-get-loadavg.cpp
        test/test-get-memory.cpp
        test/test-get-passwd.cpp
        test/test-getaddrinfo.cpp
        test/test-gethostname.cpp
        test/test-getnameinfo.cpp
        test/test-getsockname.cpp
        test/test-getters-setters.cpp
        test/test-gettimeofday.cpp
        test/test-handle-fileno.cpp
        test/test-homedir.cpp
        test/test-hrtime.cpp
        test/test-idle.cpp
        test/test-idna.cpp
        test/test-iouring-pollhup.cpp
        test/test-ip4-addr.cpp
        test/test-ip6-addr.cpp
        test/test-ip-name.cpp
        test/test-ipc-heavy-traffic-deadlock-bug.cpp
        test/test-ipc-send-recv.cpp
        test/test-ipc.cpp
        test/test-loop-alive.cpp
        test/test-loop-close.cpp
        test/test-loop-configure.cpp
        test/test-loop-handles.cpp
        test/test-loop-stop.cpp
        test/test-loop-time.cpp
        test/test-metrics.cpp
        test/test-multiple-listen.cpp
        test/test-mutexes.cpp
        test/test-not-readable-nor-writable-on-read-error.cpp
        test/test-not-writable-after-shutdown.cpp
        test/test-osx-select.cpp
        test/test-pass-always.cpp
        test/test-ping-pong.cpp
        test/test-pipe-bind-error.cpp
        test/test-pipe-close-stdout-read-stdin.cpp
        test/test-pipe-connect-error.cpp
        test/test-pipe-connect-multiple.cpp
        test/test-pipe-connect-prepare.cpp
        test/test-pipe-getsockname.cpp
        test/test-pipe-pending-instances.cpp
        test/test-pipe-sendmsg.cpp
        test/test-pipe-server-close.cpp
        test/test-pipe-set-fchmod.cpp
        test/test-pipe-set-non-blocking.cpp
        test/test-platform-output.cpp
        test/test-poll-close-doesnt-corrupt-stack.cpp
        test/test-poll-close.cpp
        test/test-poll-closesocket.cpp
        test/test-poll-multiple-handles.cpp
        test/test-poll-oob.cpp
        test/test-poll.cpp
        test/test-process-priority.cpp
        test/test-process-title-threadsafe.cpp
        test/test-process-title.cpp
        test/test-queue-foreach-delete.cpp
        test/test-random.cpp
        test/test-readable-on-eof.cpp
        test/test-ref.cpp
        test/test-run-nowait.cpp
        test/test-run-once.cpp
        test/test-semaphore.cpp
        test/test-shutdown-close.cpp
        test/test-shutdown-eof.cpp
        test/test-shutdown-simultaneous.cpp
        test/test-shutdown-twice.cpp
        test/test-signal-multiple-loops.cpp
        test/test-signal-pending-on-close.cpp
        test/test-signal.cpp
        test/test-socket-buffer-size.cpp
        test/test-spawn.cpp
        test/test-stdio-over-pipes.cpp
        test/test-strscpy.cpp
        test/test-strtok.cpp
        test/test-tcp-alloc-cb-fail.cpp
        test/test-tcp-bind-error.cpp
        test/test-tcp-bind6-error.cpp
        test/test-tcp-close-accept.cpp
        test/test-tcp-close-after-read-timeout.cpp
        test/test-tcp-close-while-connecting.cpp
        test/test-tcp-close.cpp
        test/test-tcp-close-reset.cpp
        test/test-tcp-connect-error-after-write.cpp
        test/test-tcp-connect-error.cpp
        test/test-tcp-connect-timeout.cpp
        test/test-tcp-connect6-error.cpp
        test/test-tcp-create-socket-early.cpp
        test/test-tcp-flags.cpp
        test/test-tcp-oob.cpp
        test/test-tcp-open.cpp
        test/test-tcp-read-stop.cpp
        test/test-tcp-read-stop-start.cpp
        test/test-tcp-rst.cpp
        test/test-tcp-shutdown-after-write.cpp
        test/test-tcp-try-write.cpp
        test/test-tcp-write-in-a-row.cpp
        test/test-tcp-try-write-error.cpp
        test/test-tcp-unexpected-read.cpp
        test/test-tcp-write-after-connect.cpp
        test/test-tcp-write-fail.cpp
        test/test-tcp-write-queue-order.cpp
        test/test-tcp-write-to-half-open-connection.cpp
        test/test-tcp-writealot.cpp
        test/test-test-macros.cpp
        test/test-thread-affinity.cpp
        test/test-thread-equal.cpp
        test/test-thread.cpp
        test/test-thread-priority.cpp
        test/test-threadpool-cancel.cpp
        test/test-threadpool.cpp
        test/test-timer-again.cpp
        test/test-timer-from-check.cpp
        test/test-timer.cpp
        test/test-tmpdir.cpp
        test/test-tty-duplicate-key.cpp
        test/test-tty-escape-sequence-processing.cpp
        test/test-tty.cpp
        test/test-udp-alloc-cb-fail.cpp
        test/test-udp-bind.cpp
        test/test-udp-connect.cpp
        test/test-udp-connect6.cpp
        test/test-udp-create-socket-early.cpp
        test/test-udp-dgram-too-big.cpp
        test/test-udp-ipv6.cpp
        test/test-udp-mmsg.cpp
        test/test-udp-multicast-interface.cpp
        test/test-udp-multicast-interface6.cpp
        test/test-udp-multicast-join.cpp
        test/test-udp-multicast-join6.cpp
        test/test-udp-multicast-ttl.cpp
        test/test-udp-open.cpp
        test/test-udp-options.cpp
        test/test-udp-send-and-recv.cpp
        test/test-udp-send-hang-loop.cpp
        test/test-udp-send-immediate.cpp
        test/test-udp-sendmmsg-error.cpp
        test/test-udp-send-unreachable.cpp
        test/test-udp-try-send.cpp
        test/test-udp-recv-in-a-row.cpp
        test/test-uname.cpp
        test/test-walk-handles.cpp
        test/test-watcher-cross-stop.cpp)

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
C compiler:    ${CMAKE_CXX_COMPILER} (${CMAKE_CXX_COMPILER_ID})
CFLAGS:        ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
")
