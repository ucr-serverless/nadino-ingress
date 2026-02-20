# NADINO's Cluster Ingress

## Testbed
Existing build has been tested on Ubuntu 22.04 with kernel 5.15. 

Note: F-stack works with Intel NICs using `igb_uio` driver and Mellanox NICs using `mlx5_core` driver.

```bash
git clone --recursive https://github.com/ucr-serverless/nadino-ingress.git
git submodule update --init --recursive
```

## Install deps
```bash
# Install byobu (optional)
sudo apt update && sudo apt install -y byobu && byobu
```

### Install conda (optional)

```
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

### Install build dependencies
```
sudo apt update && sudo apt install -y flex bison build-essential dwarves libssl-dev libelf-dev \
                    libnuma-dev pkg-config python3-pip python3-pyelftools \
                    libconfig-dev golang clang gcc-multilib uuid-dev sysstat gawk libpcre3 libpcre3-dev libglib2.0-dev

pip3 install meson ninja
pip3 install pyelftools --upgrade
```

### Install OFED driver for Mellanox NICs (skip for Intel NICs)

Mellanox NICs use the `mlx5` Poll Mode Driver (PMD) built into DPDK, which operates on top of
the standard `mlx5_core` kernel driver — no rebinding to `igb_uio` is required. However, DPDK's
mlx5 PMD needs the OFED (OpenFabrics Enterprise Distribution) or `rdma-core` user-space libraries
to be present **before** DPDK is compiled. Install them now:

```bash
cd ~/nadino-ingress/RDMA_lib/scripts/
bash install_ofed_driver.sh
sudo /etc/init.d/openibd restart   # load the newly installed drivers
sudo reboot                        # reboot so mlx5_core reloads cleanly and IP addrs are restored
```

After the reboot, verify the driver is loaded:
```bash
lsmod | grep mlx5
# Expected output includes: mlx5_core, mlx5_ib (or similar)
```

## Build DPDK and F-stack

> **Mellanox users**: OFED must be installed before this step so that the mlx5 PMD is compiled
> into DPDK automatically. If you install OFED after building DPDK, you must rebuild DPDK.

```bash
# Compile DPDK (21.11)
cd ~/nadino-ingress/f-stack/dpdk/
meson setup -Denable_kmods=true build
ninja -C build
ninja -C build install
# if run with normal user, the installation may get privilege error. Then run with sudo instead
sudo ninja -C build install
```

### Set hugepage at system-wide

(Option#1)

```
sudo sysctl -w vm.nr_hugepages=16384
```

```
# Set hugepage (Option#2)
# single-node system (Option#2) (use root)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# or NUMA (Option#2) (use root)
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
```

### Using Hugepage with the DPDK
```
sudo mkdir /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
```

```
# Close ASLR; it is necessary in multiple process (use root)
# execute this command with root
echo 0 > /proc/sys/kernel/randomize_va_space
```

### Setup PMD

**Intel NICs** — bind to `igb_uio` and comment out `pci_whitelist` in `f-stack.conf`:

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

**Mellanox NICs** — no driver rebinding is needed. DPDK's built-in mlx5 PMD works directly on
top of the `mlx5_core` kernel driver. Instead, you identify the NIC to DPDK by its PCIe address
using the `pci_whitelist` option in `conf/f-stack.conf`.

#### Step 1 — Find the PCIe address of your Mellanox NIC

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

#### Step 2 — Set `pci_whitelist` in `conf/f-stack.conf`

```ini
[dpdk]
# Tell DPDK which Mellanox NIC to use (PCIe address from dpdk-devbind.py)
pci_whitelist=0000:63:00.0
```

When only one device is whitelisted, DPDK assigns it **port index 0** internally, regardless of
the order shown by `dpdk-devbind.py`. Therefore set `port_list=0` and configure `[port0]` (see
the f-stack config section below).

If you whitelist multiple devices (e.g. for bonding), they are assigned port indices 0, 1, …
in the order they appear in `pci_whitelist`.

> **Intel NICs**: comment out or remove the `pci_whitelist` line — DPDK will discover all
> `igb_uio`-bound devices automatically and port indices follow `dpdk-devbind.py` order.

#### Step 3 — Remove the kernel IP address from the NIC

DPDK takes exclusive ownership of the NIC's packet path. Remove the IP address that the kernel
assigned so there is no conflict:

```bash
# Replace <ip_addr> and <dev_name> with your values (e.g. 10.10.1.3 and enp99s0f0)
sudo ip addr del <ip_addr>/24 dev <dev_name>

# Verify the address is gone
ip addr show <dev_name>
```

The interface stays up and `mlx5_core` remains loaded — only the IP is removed.

### f-stack config (`conf/f-stack.conf`)

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

## Compile and install F-Stack
```
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

### Install DOCA Lib

Please refer to the original documentation.

Our project is tested under DOCA 2.9.1 to 2.10

```bash
cd ~
wget https://www.mellanox.com/downloads/DOCA/DOCA_v2.9.1/host/doca-host_2.9.1-018000-24.10-ubuntu2204_amd64.deb
sudo dpkg -i doca-host_2.9.1-018000-24.10-ubuntu2204_amd64.deb
sudo apt-get update
sudo apt-get -y install doca-all
```

# Install DOCA Lib
```
cd ~/nadino-ingress/DOCA_lib
meson /tmp/doca_lib
ninja -C /tmp/doca_lib
```

## Build NADINO Ingress

```bash
cd ~/nadino-ingress/
FF_PATH=~/nadino-ingress/f-stack PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
# For debugging: ./configure --prefix=/usr/local/nginx_fstack --with-ff_module --with-debug
```

# NOTE 1: Add HTTP_DEPS and HTTP_INCS to pdi_rdma in objs/Makefile
After the `.configure` step, open the `objs/Makefile` and manually change the `pdi_rdma.o` compilation command into the following

*NOTE: Add HTTP_DEPS and HTTP_INCS to pdi_rdma in objs/Makefile*
```
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
        "-p", "10000",
        "-g", "3"
    };


# Compile NADINO Ingress
make -j
sudo make install
```

## Enable HTTP-RDMA adaptor in NADINO Ingress
Alternatively, run `python ./scripts/patch_make.py` to update the Makefile automatically.

```bash
FF_PATH=~/nadino-ingress/f-stack PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig make -j
sudo make install
```

## Change configs

The f-stack related configs are located in `conf/f-stack.conf`, which will be read into `./conf/nginx.conf` and pass to NGINX.

After you have changed configs in the nadino-ingress source, use `sudo make install` to synchronize the change then restart the NGINX

## Enable HTTP-RDMA adaptor in nadino Ingress
We use the NGINX location block to enable HTTP-RDMA adaptor. The command used for HTTP-RDMA adaptor is `palladium_ingress`. The command used for the regular HTTP reverse proxy is still `proxy_pass`. An example configuration of HTTP-RDMA adaptor is shown below:

To enable the rdma and f-stack path, edit the `./conf/nginx.conf` and add the following content inside the existing server block.

NOTE: to enable the `/rdma`, you should either use the simple server in `./microbench/` or full-fledged [naidno-network-engine](https://github.com/ucr-serverless/nadino-network-engine)

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

Before starting, verify the installed f-stack config matches your NIC setup:
```bash
# The installed config is a copy of conf/f-stack.conf placed by `sudo make install`
# Edit directly after install, or edit the source and re-run `sudo make install`
sudo vim /usr/local/nginx_fstack/conf/f-stack.conf
```

### Binding a NIC to F-stack (`conf/f-stack.conf`)

This is a summary of how port assignments work. See the "Setup PMD" section above for the full
step-by-step instructions.

**Mellanox NICs** (`mlx5_core` driver — no rebinding needed):

1. Find your NIC's PCIe address:
   ```bash
   python ~/nadino-ingress/f-stack/dpdk/usertools/dpdk-devbind.py --status
   ```
   Example output:
   ```
   Network devices using kernel driver
   =====================================
   0000:01:00.0 'MT27800 Family [ConnectX-5]' if=eno33np0    drv=mlx5_core *Active*
   0000:01:00.1 'MT27800 Family [ConnectX-5]' if=eno34np1    drv=mlx5_core
   0000:41:00.0 'MT27800 Family [ConnectX-5]' if=enp65s0f0   drv=mlx5_core *Active*
   0000:41:00.1 'MT27800 Family [ConnectX-5]' if=enp65s0f1   drv=mlx5_core
   ```

2. Set `pci_whitelist` in `f-stack.conf` to the PCIe address of your chosen NIC. DPDK assigns
   the **first (and only) whitelisted device port index 0**, regardless of its position in the
   `dpdk-devbind.py` output. Use `port_list=0` and `[port0]`:
   ```ini
   # Example: use enp65s0f0 (PCIe 0000:41:00.0)
   pci_whitelist=0000:41:00.0

   port_list=0

   [port0]
   addr=10.10.1.3        # IP formerly assigned to enp65s0f0 under the kernel
   netmask=255.255.255.0
   broadcast=10.10.1.255
   gateway=10.10.1.1
   ```

3. Remove the IP address from the NIC so the kernel does not conflict with DPDK:
   ```bash
   sudo ip addr del 10.10.1.3/24 dev enp65s0f0
   ```

**Intel NICs** (`igb_uio` driver — must be rebound to DPDK first): port indices follow
`dpdk-devbind.py` order after rebinding. Comment out `pci_whitelist` and set `port_list` to the
port's position in that list.

```bash
# Run NGINX not as a daemon
sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"
```

**Worker process scaling**: by default only one worker process is created. To add more, set
`worker_processes` in `nginx.conf` **and** update `lcore_mask` in `f-stack.conf` to a bitmask
with one bit per worker (e.g. `lcore_mask=3` for two workers on cores 0 and 1).

```bash
# Print F-stack startup messages in syslog
sudo grep "f-stack" /var/log/syslog

# Stream NGINX runtime logs
tail -f /usr/local/nginx_fstack/logs/error.log
```

> **Note**: F-stack applies a 100 µs TX packet delay (`pkt_tx_delay`) when fewer than 32 packets
> are queued. This reduces RPS and increases latency at low concurrency. Set `pkt_tx_delay=0` in
> `f-stack.conf` to disable it if you need minimum latency.

### test with simple backend

```
meson setup /tmp/rdma_server/ microbench/
ninja -C /tmp/rdma_server/
```

run the client first with 

```bash
/tmp/rdma_server/rdma_server -d <rdma device> -n 1000 -s 1024 -a <socket_server_ip> -p <socket_server_port> -g <gid_index>
```


## How to add new source file?

NGINX documentation is available at http://nginx.org

Create new files, include the two necessary header file, according to [nginx development guide](https://nginx.org/en/docs/dev/development_guide.html)

```c
#include <ngx_config.h>
#include <ngx_core.h>
```

Add file to compilation system by adding new file in `auto/sources`

## How to add new compilation flags?

To add a new CFLAGS, just add new lines in `auto/make`

To add new library, add new libraries to `CORE_LIBS` in `auto/make`
