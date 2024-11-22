#!/bin/sh

# install the ofed driver on CPU
# do not use this on bluefield DPU
bash RDMA_lib/scripts/install_ofed_driver.shbash RDMA_lib/scripts/install_ofed_driver.sh
sudo apt update && sudo apt install -y flex bison build-essential dwarves libssl-dev libelf-dev \
                    libnuma-dev pkg-config python3-pip python3-pyelftools \
                    libconfig-dev golang clang gcc-multilib uuid-dev sysstat gawk libpcre3 libpcre3-dev libglib2.0-dev
pip3 install meson ninja
pip3 install pyelftools --upgrade
cd palladium-ingress/f-stack/dpdk/
meson setup -Denable_kmods=true build
ninja -C build
ninja -C build install

sudo sysctl -w vm.nr_hugepages=16384
sudo mkdir /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

sudo echo 0 > /proc/sys/kernel/randomize_va_space
