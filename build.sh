#!/bin/bash

PROJECT_ROOT=$(git rev-parse --show-toplevel)
BUILD_DIR=${PROJECT_ROOT}/build
INSTALL_DIR=${PROJECT_ROOT}/install
pushd ${BUILD_DIR}
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} \
    -DLIBUV_BUILD_TESTS=ON \
    -DLIBUV_BUILD_BENCH=ON \
    ..
make -j`nproc`
make install
popd
