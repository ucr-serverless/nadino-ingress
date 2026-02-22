# NADINO's Cluster Ingress

## Requirements

Existing build has been tested on Ubuntu 22.04 with kernel 5.15.

NADINO requires two NICs to work properly; one NIC must be NVIDIA/Mellanox NIC to support RDMA traffic.

Another NIC will work with DPDK for normal HTTP traffic.

Later we will refer to them as RDMA NIC and DPDK NIC respectively.

Note: F-stack works with Intel NICs using `igb_uio` driver and Mellanox NICs using `mlx5_core` driver.

The configuration file shipped with the NADINO is used on cloudlab [`r7525`](https://docs.cloudlab.us/hardware.html) nodes.

In particular, you should create the experiment with our customized [network profile](https://www.cloudlab.us/p/KKProjects/dpu-same-lan).

## Getting Started

```bash
git clone --recursive https://github.com/ucr-serverless/nadino-ingress.git
cd nadino-ingress
git submodule update --init --recursive
```

## Installation

### 1. Install Dependencies

```bash
# Install byobu (optional)
sudo apt update && sudo apt install -y byobu && byobu
```

#### Install conda (optional)

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-py39_23.3.1-0-Linux-x86_64.sh
chmod +x Miniconda3-py39_23.3.1-0-Linux-x86_64.sh
bash Miniconda3-py39_23.3.1-0-Linux-x86_64.sh -b -p ~/miniconda3
source ~/miniconda3/bin/activate
conda init bash
source $HOME/.bashrc

# Create conda env (optional)
conda create -n ingress python=3.10 -y
conda activate ingress
```

#### Install build dependencies

```bash
sudo apt update && sudo apt install -y flex bison build-essential dwarves libssl-dev libelf-dev \
                    libnuma-dev pkg-config python3-pip python3-pyelftools \
                    libconfig-dev golang clang gcc-multilib uuid-dev sysstat gawk libpcre3 libpcre3-dev libglib2.0-dev

pip3 install meson ninja
pip3 install pyelftools --upgrade
```

### 2. Install DOCA (RDMA NIC driver)

On the host, install the DOCA-host package, which will install RDMA driver (mlx5) and related softwares.

If your DPDK NIC happens to be a Mellanox one, which is the case for r7525 nodes on cloudlab, you can do not to setup `igb_uio`.

```bash
wget https://www.mellanox.com/downloads/DOCA/DOCA_v2.10.0/host/doca-host_2.10.0-093000-25.01-ubuntu2204_amd64.deb
sudo dpkg -i doca-host_2.10.0-093000-25.01-ubuntu2204_amd64.deb
sudo apt-get update
sudo apt-get -y install doca-all
```

Mellanox NICs use the `mlx5` Poll Mode Driver (PMD) built into DPDK, which operates on top of
the standard `mlx5_core` kernel driver — no rebinding to `igb_uio` is required. However, DPDK's
mlx5 PMD needs the OFED (OpenFabrics Enterprise Distribution) or `rdma-core` user-space libraries
to be present **before** DPDK is compiled.

Verify the driver is loaded:

```bash
lsmod | grep mlx5
# Expected output includes: mlx5_core, mlx5_ib (or similar)
```


### 4. Configure Hugepages

**Option 1** — system-wide via sysctl:

```bash
sudo sysctl -w vm.nr_hugepages=16384
```

**Option 2** — direct kernel interface (run as root):

```bash
# Single-node system
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# NUMA system
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
```

Mount the hugepage filesystem and disable ASLR (required for DPDK multi-process):

```bash
sudo mkdir /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Disable ASLR (run as root)
echo 0 > /proc/sys/kernel/randomize_va_space
```

### 5. Setup PMD (NIC Driver Binding)


#### Intel NICs — bind to `igb_uio`
*NOTE*: this step is only required if you DPDK NIC is a intel one.

```bash
# Install and load the igb_uio driver
modprobe uio
insmod f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.ko
insmod f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko carrier=on

# Bind the NIC to DPDK
python f-stack/dpdk/usertools/dpdk-devbind.py --status
ifconfig eth0 down
python f-stack/dpdk/usertools/dpdk-devbind.py --bind=igb_uio eth0
```

Comment out the `pci_whitelist` line in `conf/f-stack.conf` — DPDK will discover all
`igb_uio`-bound devices automatically, and port indices follow `dpdk-devbind.py` order.

#### Mellanox NICs — no driver rebinding needed

DPDK's built-in mlx5 PMD works directly on top of the `mlx5_core` kernel driver. You identify
the NIC to DPDK by its PCIe address using the `pci_whitelist` option in `conf/f-stack.conf`.

**Step 1 — Find the PCIe address of your Mellanox NIC:**

```bash
python ~/nadino-ingress/f-stack/dpdk/usertools/dpdk-devbind.py --status
```

Example output:
```
Network devices using kernel driver
=====================================
0000:01:00.0 'MT27800 Family [ConnectX-5]' if=eno33np0  drv=mlx5_core unused=vfio-pci *Active*
0000:01:00.1 'MT27800 Family [ConnectX-5]' if=eno34np1  drv=mlx5_core unused=vfio-pci
0000:63:00.0 'MT27800 Family [ConnectX-5]' if=enp99s0f0 drv=mlx5_core unused=vfio-pci *Active*
0000:63:00.1 'MT27800 Family [ConnectX-5]' if=enp99s0f1 drv=mlx5_core unused=vfio-pci
```

Pick the interface you want F-stack to own (e.g. `enp99s0f0` at `0000:63:00.0`).

**Step 2 — Set `pci_whitelist` in `conf/f-stack.conf`:**

```ini
[dpdk]
# Tell DPDK which Mellanox NIC to use (PCIe address from dpdk-devbind.py)
pci_whitelist=0000:63:00.0
```

When only one device is whitelisted, DPDK assigns it **port index 0** internally, regardless of
the order shown by `dpdk-devbind.py`. Therefore set `port_list=0` and configure `[port0]` (see
the Configuration section below).

If you whitelist multiple devices (e.g. for bonding), they are assigned port indices 0, 1, …
in the order they appear in `pci_whitelist`.

**Step 3 — Remove the kernel IP address from the NIC:**

DPDK takes exclusive ownership of the NIC's packet path. Remove the IP address that the kernel
assigned so there is no conflict:

```bash
# Replace <ip_addr> and <dev_name> with your values (e.g. 10.10.1.3 and enp99s0f0)
sudo ip addr del <ip_addr>/24 dev <dev_name>

# Verify the address is gone
ip addr show <dev_name>
```

The interface stays up and `mlx5_core` remains loaded — only the IP is removed.

## Build

We assume your pwd is under the root of nadino-ingress
### Build RDMA Lib

```bash
cd ./RDMA_lib
make
```

### Build DOCA Lib

Our project is tested under DOCA 2.9.1 to 2.10.

```bash
cd ./DOCA_lib
meson /tmp/doca_lib
ninja -C /tmp/doca_lib
```

If you encounter build error for DOCA_lib, try remove the existing build at `/tmp/doca_lib` with `sudo rm -rf /tmp/doca_lib` and try again

### Build DPDK and F-stack

> **Mellanox users**: DOCA-host must be installed before this step so that the mlx5 PMD is compiled
> into DPDK automatically. If you install DOCA-host after building DPDK, you must rebuild DPDK.

Compile DPDK (21.11)

```bash
cd ./f-stack/dpdk/
meson setup -Denable_kmods=true build
ninja -C build
sudo ninja -C build install
```

## Compile and install F-Stack

We assume your nadino-ingress is located under the root, if it is not, please change the `FF_PATH` accordingly.

```
export FF_PATH=~/nadino-ingress/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
cd ~/nadino-ingress/f-stack/lib/
make -j
sudo make install
```

### Build NADINO Ingress

```bash
FF_PATH=~/nadino-ingress/f-stack PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
python ./scripts/patch_make.py
FF_PATH=~/nadino-ingress/f-stack PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig make -j
sudo make install
```

> **Note**: For debugging: `./configure --prefix=/usr/local/nginx_fstack --with-ff_module --with-debug`

> **Note**: `./scripts/patch_make.py` adds `HTTP_DEPS` and `HTTP_INCS` to `pdi_rdma` in `objs/Makefile`.

> **Note**: If your nadino directory is not under the home directory, change `FF_PATH` accordingly.

### Build Microbench (optional)

```bash
meson setup /tmp/rdma_server/ microbench/
ninja -C /tmp/rdma_server/
```

## Configuration

### Config File Reference

| Config file | Purpose |
|---|---|
| `conf/f-stack.conf` | DPDK/F-stack settings (port, hugepages, lcore mask) |
| `conf/nginx.conf`   | NGINX settings (worker count, location blocks) |
| `conf/rdma.cfg`     | RDMA connection parameters (device, IP, port, GID) — read at runtime, no recompile needed |

After editing any config file, run `sudo make install` to copy it to the installed
directory (`/usr/local/nginx_fstack/conf/`), then restart NGINX.

### F-stack Config (`conf/f-stack.conf`)

The `[port0]` section defines the IP configuration that the F-stack (FreeBSD) network stack
presents to NGINX. Set it to the values the NIC had under the kernel:

```ini
port_list=0          # must match the DPDK port index (0 when one device is whitelisted)

[port0]
addr=10.10.1.3       # IP address previously on the NIC
netmask=255.255.255.0
broadcast=10.10.1.255
gateway=10.10.1.1
```

`lcore_mask` controls which CPU cores DPDK polls on. It must match the number of
`worker_processes` in `nginx.conf` (one bit per worker). For example, `lcore_mask=1` uses only
core 0 — appropriate for a single worker process.

**Worker process scaling**: to add more workers, set `worker_processes` in `nginx.conf` **and**
update `lcore_mask` in `f-stack.conf` to a bitmask with one bit per worker (e.g. `lcore_mask=3`
for two workers on cores 0 and 1).

> **Note**: F-stack applies a 100 µs TX packet delay (`pkt_tx_delay`) when fewer than 32 packets
> are queued. This reduces RPS and increases latency at low concurrency. Set `pkt_tx_delay=0` in
> `f-stack.conf` to disable it if you need minimum latency.

### NGINX Config — Enable HTTP-RDMA Adaptor (`conf/nginx.conf`)

Use the NGINX location block to enable the HTTP-RDMA adaptor. The directive for the HTTP-RDMA
adaptor is `palladium_ingress`; regular HTTP reverse proxy still uses `proxy_pass`.

> **Note**: To enable the `/rdma` route, you need either the simple server in `./microbench/` or
> the full-fledged [nadino-network-engine](https://github.com/ucr-serverless/nadino-network-engine).

> **Note**: The config has been pre-filled for you already.

```nginx
http {
    ...
    server {
        ...

        # We use comma to separate worker node addresses
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

### RDMA Config (`conf/rdma.cfg`)

RDMA parameters are read from `conf/rdma.cfg` at runtime — **no recompilation required**.

Open `conf/rdma.cfg` and set the values for your deployment:

```ini
# RDMA/DOCA device name — run 'doca_tools list_devices' or check
# /sys/class/infiniband/ to find the name for your Mellanox NIC.
device = mlx5_0

# Message size in bytes — must equal sizeof(struct http_transaction).
msg_sz = 31920

# IP address of the DNE (Distributed Network Engine) backend server.
server_ip = 128.110.219.40

# TCP port on the DNE server used for the RDMA control-path handshake.
server_port = 10000

# GID index for the RDMA device (3 = RoCEv2 on most CloudLab setups).
gid_idx = 3
```

After editing `conf/rdma.cfg`, run `sudo make install` to copy it to
`/usr/local/nginx_fstack/conf/`, then restart NGINX.

## Running NADINO Ingress

Before starting, verify the installed f-stack config matches your NIC setup:

```bash
# The installed config is a copy of conf/f-stack.conf placed by `sudo make install`.
# Edit it directly after install, or edit the source and re-run `sudo make install`.
sudo vim /usr/local/nginx_fstack/conf/f-stack.conf
```

Run NGINX (not as a daemon):

```bash
sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"
```

Monitor startup and runtime logs:

```bash
# Print F-stack startup messages in syslog
sudo grep "f-stack" /var/log/syslog

# Stream NGINX runtime logs
tail -f /usr/local/nginx_fstack/logs/error.log
```

## Testing

### Test with Simple Backend

The simple backend is located on the same node and offer a local test.

Build the microbench RDMA server (if not already built):

```bash
meson setup /tmp/rdma_server/ microbench/
ninja -C /tmp/rdma_server/
```

Run the RDMA server:

```bash
/tmp/rdma_server/rdma_server -d <rdma device> -n 1000 -s 31920 -a <socket_server_ip> -p <socket_server_port> -g <gid_index>
```

Then change the `rdma.cfg`; Change the IP address to the <socket_server_ip>`

Run the nadino-ingress:

```bash
sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"
```


### Test with nadino-network-engine

After the online boutique function chain [set up](https://github.com/ucr-serverless/nadino-network-engine/blob/main/README.md)
and network engine and ingress connected, run the following commands to test different online-boutique routes:

*NOTE*: 
```bash
wrk -t1 -c50 -d10s http://10.10.1.3:80/rdma/1/cart -H "Connection: Close"

wrk -t1 -c50 -d10s http://10.10.1.3:80/rdma/1/ -H "Connection: Close"

wrk -t1 -c50 -d10s "http://10.10.1.3:80/rdma/1product?1YMWWN1N4O" -H "Connection: Close"
```

## Troubleshooting

**NADINO Ingress silently exits after `f-stack -c1 -n4 --proc-type=primary --allow=0000:63:00.0`**

This is usually a DPDK initialization failure. Check the log for the detailed reason:

```bash
tail -f /usr/local/nginx_fstack/logs/error.log
```

(The log accumulates across runs, so check the tail.)

---

**Error**: `Cannot create lock on '/var/run/dpdk/rte/config'. Is another primary process running?`

Another DPDK main process is already running. Kill it and restart:

```bash
pkill nginx
```

---

**Error**: `No free 2048 kB hugepages reported on node 0`

No hugepages are allocated. Allocate them and retry:

```bash
sudo sysctl -w vm.nr_hugepages=32768
```

## Development

### Adding a New Source File

NGINX documentation is available at http://nginx.org

Create new files and include the two necessary header files, per the
[nginx development guide](https://nginx.org/en/docs/dev/development_guide.html):

```c
#include <ngx_config.h>
#include <ngx_core.h>
```

Add the new file to the compilation system by listing it in `auto/sources`.

### Adding New Compilation Flags

To add a new `CFLAGS`, add new lines in `auto/make`.

To add a new library, append it to `CORE_LIBS` in `auto/make`.
