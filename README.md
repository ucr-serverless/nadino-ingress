# NADINO's Cluster Ingress

## Testbed
Existing build has been tested on Ubuntu 22.04 with kernel 5.15. 

Note: F-stack works with Intel NICs using `igb_uio` driver and Mellanox NICs using `mlx5_core` driver.

```bash
git clone --recursive https://github.com/ucr-serverless/nadino-ingress.git
```

## Install deps
```bash
# Install byobu (optional)
sudo apt update && sudo apt install -y byobu && byobu

# Install conda (optional)
wget https://repo.anaconda.com/miniconda/Miniconda3-py39_23.3.1-0-Linux-x86_64.sh
chmod +x Miniconda3-py39_23.3.1-0-Linux-x86_64.sh
bash Miniconda3-py39_23.3.1-0-Linux-x86_64.sh -b -p ~/miniconda3
source ~/miniconda3/bin/activate
conda init bash
source $HOME/.bashrc

# Create conda env (optional)
conda create -n ingress python=3.10 -y
conda activate ingress

# Install build dependencies (TODO: remove unnecessary deps)
sudo apt update && sudo apt install -y flex bison build-essential dwarves libssl-dev libelf-dev \
                    libnuma-dev pkg-config python3-pip python3-pyelftools \
                    libconfig-dev golang clang gcc-multilib uuid-dev sysstat gawk libpcre3 libpcre3-dev libglib2.0-dev

pip3 install meson ninja
pip3 install pyelftools --upgrade

# To get F-stack to work with Mellanox NICs, install the `mlx5_core` driver.
# Skip this step if you get F-stack to work with Intel NICs
cd nadino-ingress/RDMA_lib/scripts/
bash install_ofed_driver.sh
sudo /etc/init.d/openibd restart # load the newly installed drivers
sudo reboot # Reboot node to load IP address
```

## Build DPDK and F-stack
```bash
# Compile DPDK (21.11)
cd nadino-ingress/f-stack/dpdk/
meson setup -Denable_kmods=true build
ninja -C build
ninja -C build install

# Set hugepage at system-wide (Option#1)
sudo sysctl -w vm.nr_hugepages=16384

# Set hugepage (Option#2)
# single-node system (Option#2) (use root)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# or NUMA (Option#2) (use root)
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

# Using Hugepage with the DPDK
sudo mkdir /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Close ASLR; it is necessary in multiple process (use root)
echo 0 > /proc/sys/kernel/randomize_va_space

# Install the DPDK driver (igb_uio) for Intel NICs (Not needed for Mellanox NICs)
modprobe uio
insmod f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.ko
insmod f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko carrier=on # carrier=on is necessary, otherwise need to be up `veth0` via `echo 1 > /sys/class/net/veth0/carrier`

# Bind NICs to DPDK (only for Intel NICs)
python dpdk-devbind.py --status
ifconfig eth0 down
python dpdk-devbind.py --bind=igb_uio eth0 # assuming that use 10GE NIC and eth0

# Compile and install F-Stack
export FF_PATH=~/nadino-ingress/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
cd ~/nadino-ingress/f-stack/lib/
make -j
sudo make install
```

## Build RDMA Lib
```bash
cd ~/nadino-ingress/RDMA_lib
make
```

## Build DOCA Lib
```bash
cd ~/

# Install DOCA packages (v2.9.1)
wget https://www.mellanox.com/downloads/DOCA/DOCA_v2.9.1/host/doca-host_2.9.1-018000-24.10-ubuntu2204_amd64.deb
sudo dpkg -i doca-host_2.9.1-018000-24.10-ubuntu2204_amd64.deb
sudo apt-get update
sudo apt-get -y install doca-all

# Install DOCA Lib
cd ~/nadino-ingress/DOCA_lib
meson /tmp/doca_lib
ninja -C /tmp/doca_lib
```

## Build NADINO Ingress
```bash
cd ~/nadino-ingress/
bash ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
# For debugging: ./configure --prefix=/usr/local/nginx_fstack --with-ff_module --with-debug

# NOTE 1: Add HTTP_DEPS and HTTP_INCS to pdi_rdma in objs/Makefile
objs/src/core/pdi_rdma.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/core/pdi_rdma.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/core/pdi_rdma.o \
		src/core/pdi_rdma.c

# NOTE 2: Update hardcoded RDMA params in pdi_rdma.c
# Go to pdin_init_rdma_config() in pdi_rdma.c
    char *argv[] = {
        "dummy",
        "-d", "mlx5_0",
        "-s", "167088",
        "-a", "128.110.219.40",
        "-p", "10000"
    };

# If need "-g"
    char *argv[] = {
        "dummy",
        "-d", "mlx5_0",
        "-s", "167088",
        "-a", "128.110.219.40",
        "-p", "10000",
        "-g", "3"
    };

# Compile NADINO Ingress
make -j
sudo make install
```

## Enable HTTP-RDMA adaptor in NADINO Ingress
We use the NGINX location block to enable HTTP-RDMA adaptor. The command used for HTTP-RDMA adaptor is `palladium_ingress`. The command used for the regular HTTP reverse proxy is still `proxy_pass`. An example configuration of HTTP-RDMA adaptor is shown below:
```
http {
    ...
    server {
        ...

        # We use comma to seperate worker node addresses
        # NOTE: We currently don't use worker node addresses
        location /rdma {
            palladium_ingress 10.10.1.2:80,10.10.1.3:80,10.10.1.4:8080;
        }

        # location block config for regular HTTP reverse proxy
        location /fstack {
            proxy_pass http://10.10.1.2:80/;
        }

        ...
    }
    ...
}
```

## Test NADINO Ingress
```bash
# Run NGINX not as a daemon
sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"

# Number of worker processes: 
# Default config creates only one worker process
# If you need more worker processes, please change both "lcore_mask" in f-stack.conf and "worker_processes" in nginx.conf
# or use HPA to adjust number of worker processes based on load level

# Print logs of NGINX
sudo cat /var/log/syslog | grep "f-stack"

# Print NGINX Runtime Logs
tail -f /usr/local/nginx_fstack/logs/error.log

# Modify F-stack configuration
sudo vim /usr/local/nginx_fstack/conf/f-stack.conf

# Bind NIC to F-stack
# You need to properly change "port_list" and "Port config section" in f-stack.conf to bind NIC to F-stack.
# The first is to get the index of port used for F-stack. I will use Cloudlab node as an example to explain.
# You will need to use "nadino-ingress/f-stack/dpdk/usertools/dpdk-devbind.py" to get the port index
cd ~/nadino-ingress/f-stack/dpdk/usertools/
python dpdk-devbind.py --status
# You will see the output as below:
Network devices using kernel driver
===================================
0000:01:00.0 'MT27800 Family [ConnectX-5] 1017' if=eno33np0 drv=mlx5_core unused=vfio-pci *Active*
0000:01:00.1 'MT27800 Family [ConnectX-5] 1017' if=eno34np1 drv=mlx5_core unused=vfio-pci
0000:41:00.0 'MT27800 Family [ConnectX-5] 1017' if=enp65s0f0np0 drv=mlx5_core unused=vfio-pci *Active*
0000:41:00.1 'MT27800 Family [ConnectX-5] 1017' if=enp65s0f1np1 drv=mlx5_core unused=vfio-pci

# The port index follows the order in the output, starting from 0
# If I want to bind eno33np0 to F-stack, the port index will be used in f-stack.conf is 0
# If I want to bind enp65s0f0np0 to F-stack, the port index will be used in f-stack.conf is 2

# Next is to update "port_list" and "Port config section" in f-stack.conf
# If I choose enp65s0f0np0 (the port index is 2), I need to specify port_list=2 in Line#59 in f-stack.conf
# I also need to change the port config section as below, replace the default [port0] with [port2],
# and update "addr", "broadcast", "gateway" accordingly
    ...
    port_list=2
    ...
    # Port config section
    # Correspond to dpdk.port_list's index: port0, port1...
    [port2]
    addr=10.10.1.1
    netmask=255.255.255.0
    broadcast=10.10.1.255
    gateway=10.10.1.1
    ...

# Important Note of f-stack.conf:
# F-stack has 100us TX packet delay time (pkt_tx_delay) while send less than 32 pkts.
# This affects RPS and latency performance at low concurrency.
```

NGINX documentation is available at http://nginx.org

## How to add new source file?

Create new files, include the two necessary header file, according to [nginx development guide](https://nginx.org/en/docs/dev/development_guide.html)

```c
#include <ngx_config.h>
#include <ngx_core.h>
```

Add file to compilation system by adding new file in `auto/sources`

## How to add new compilation flags?

To add a new CFLAGS, just add new lines in `auto/make`

To add new library, add new libraries to `CORE_LIBS` in `auto/make`
