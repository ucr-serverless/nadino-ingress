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
                    libconfig-dev golang clang gcc-multilib uuid-dev sysstat gawk libpcre3 libpcre3-dev

pip3 install meson ninja
pip3 install pyelftools --upgrade

# Compile DPDK (21.11)
cd palladium-ingress/f-stack/dpdk/
meson setup -Denable_kmods=true build
ninja -C build
ninja -C build install

# Set hugepage at system-wide (Option#1)
sudo sysctl -w vm.nr_hugepages=16384

# Set hugepage (Option#2)
# single-node system (Option#2)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# or NUMA (Option#2)
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

# Using Hugepage with the DPDK
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Close ASLR; it is necessary in multiple process
echo 0 > /proc/sys/kernel/randomize_va_space

# Install the DPDK driver (igb_uio) for Intel NICs (Not needed for Mellanox NICs)
modprobe uio
insmod f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.ko
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
make -j
sudo make install
```

## Test Palladium Ingress
```bash
# Run NGINX not as a daemon
sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"

# Print logs of NGINX
sudo cat /var/log/syslog | grep "f-stack"

# Modify F-stack configuration
sudo vim /usr/local/nginx_fstack/conf/f-stack.conf
```

NGINX documentation is available at http://nginx.org

