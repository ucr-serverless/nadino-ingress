# Palladium Ingress

## Testbed
Existing build has been tested on c220g* nodes on Cloudlab Wisc, using 
Ubuntu 22.04 with kernel 5.15.
Note: F-stack works with Intel NICs using `igb_uio` driver.

```bash
git clone --recursive https://github.com/ucr-serverless/palladium-ingress.git
```

## Build F-stack
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

# Compile DPDK (21.11)
cd palladium-ingress/f-stack/dpdk/
meson setup -Denable_kmods=true build
ninja -C build
sudo ninja -C build install

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

# establish channel between DPDK and kernel stack
insmod f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko carrier=on # carrier=on is necessary, otherwise need to be up `veth0` via `echo 1 > /sys/class/net/veth0/carrier`

# Bind NICs to DPDK
python dpdk-devbind.py --status
ifconfig eth0 down
python dpdk-devbind.py --bind=igb_uio eth0 # assuming that use 10GE NIC and eth0

# Compile and install F-Stack
export FF_PATH=~/palladium-ingress/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
cd ~/palladium-ingress/f-stack/lib/
make -j
sudo make install
```

## Build Palladium Ingress (NGINX)
```bash
cd ~/palladium-ingress/
bash ./configure --prefix=/usr/local/nginx_fstack --with-ff_module

# For debugging: ./configure --prefix=/usr/local/nginx_fstack --with-ff_module --with-debug

make -j
sudo make install
```

## Test Palladium Ingress
```bash
# Run NGINX not as a daemon
sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"
# Run the NGINX with rdma configuration
sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;" -C /usr/local/nginx_fstack/conf/rdma.cfg

# check runtime log
tail -f /usr/local/nginx_fstack/log/error.log
# Print logs of NGINX
sudo cat /var/log/syslog | grep "f-stack"

# Modify F-stack configuration
sudo vim /usr/local/nginx_fstack/conf/f-stack.conf
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

## how to change the config of f-stack and nginx?

First, edit the `nginx.conf`, if we wants to edit the number of worker process, we need to change the
`worker_processes  1;` line in the `nginx.conf`

Then, we need to change the `lcore_mask` value in `f-stack.conf`. If we use 3 worker process, we need to set the mask to `111`, which has same amount of `1` with the process number

Afterwards, we need to edit the `port_list` the port settings.

The available port can be get using dpdk's user tool.

It is located under the f-stack installation folder, the relative path is `<f-stack>/dpdk/usertools/dpdk-devbind.py -s`

Run the command with `python dpdk-devbind.py -s` and get the correct port number

Change the port list to the port we want to use and edit the corresponding port settings.
For example, if we want to use `port1`, then we need to add a field of `port1` and change the `addr`, `netmask`, `broadcast` and `gateway` settings accordingly.


## How to test RDMA?

First, change the `rdma.cfg` file under the `conf` directory, change the hostname of nodes setting

The ip address and the `contro_server_port` will be used to create TCP socket connection, which will be used by RDMA to change out of band information  to establish connection.

The IP address should be change to a different address which the f-stack occupies.

Then change the `device_idx`, `sgid_idx` and `ib_port` accordingly based on the result from `RDMA_lib/scripts/get_cloudlab_node_settings.py`

uncomment the `/rdma` upstream in `nginx.conf` and change the upstream ip

```
        # location /rdma {
        #     palladium_ingress http://10.10.1.2:80/;
        # }
```

Use the `curl http://10.10.1.3:80 -v` to test the normal connection to the nginx.
Use the `curl http://10.10.1.3:80/rdma -v` to test the connection to the rdma upstream.

## How to change log level of nginx

Change the `error_log log/error.log` line in `nginx.conf` file.
The nginx will load configuration files under `/usr/local/nginx_fstack/conf/`
If we want debug logs, append the setting with the debug keyword, like `error_log  logs/error.log debug;`
