#!/bin/bash

#!/bin/bash

rootDir=$(git rev-parse --show-toplevel)

pushd ${rootDir}/build
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DCMAKE_INSTALL_PREFIX=${rootDir}/install \
    -DLIBUV_BUILD_TESTS=ON \
    -DLIBUV_BUILD_BENCH=ON \
    ..
make -j`nproc`
make install
popd
