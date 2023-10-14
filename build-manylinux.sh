#!/bin/bash
set -ex
yum install epel-release
yum repolist
yum install zlib zlib-devel libpcap libpcap-devel SDL2-devel agg-devel soundtouch-devel openal-soft-devel glib2-devel libtool autoconf automake meson -y

# Posix C-Source required for some time constants.
export CXXFLAGS="-DFORCE_AVX512_0=1 -D_POSIX_C_SOURCE=199309L"
export CFLAGS="-D_POSIX_C_SOURCE=199309L"

# fun! I love CentOS 7!!!
cat << 'EOF' > /usr/lib64/pkgconfig/libpcap.pc
prefix="/usr"
exec_prefix="${prefix}"
includedir="${prefix}/include"
libdir="${exec_prefix}/lib"

Name: libpcap
Description: Platform-independent network traffic capture library
Version: 1.53.3
Libs: -L${libdir}  -lpcap
Cflags: -I${includedir}
EOF

curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain stable -y
source $HOME/.cargo/env
