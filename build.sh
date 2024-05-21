#!/bin/bash

pushd /home/endinferno/project/libuv/build
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DCMAKE_INSTALL_PREFIX=/home/endinferno/project/libuv/install \
    -DLIBUV_BUILD_TESTS=ON \
    -DLIBUV_BUILD_BENCH=ON \
    ..
make -j`nproc`
make install
popd
