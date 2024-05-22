#!/bin/bash

find src -regex '.*\.\(cpp\|h\)' -exec clang-format -style=file -i {} \;
find include -regex '.*\.\(cpp\|h\)' -exec clang-format -style=file -i {} \;
find test -regex '.*\.\(cpp\|h\)' -exec clang-format -style=file -i {} \;
