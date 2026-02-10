# Justfile
# a just file for development only
build:
    FF_PATH=~/nadino-ingress/f-stack PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig make -j
    meson setup /tmp/rdma_server/ microbench/
    ninja -C /tmp/rdma_server/

install:
    sudo make install
run:
    sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"

bear:
    bear -- make

make:
    FF_PATH=~/nadino-ingress/f-stack PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
    python ./scripts/patch_make.py

kill:
    sudo pkill -i nginx

alias ks := kill_server
kill_server:
    sudo pkill -i rdma_server

server server_IP:
    /tmp/rdma_server/rdma_server -d mlx5_2 -n 1000 -s 31930 -a {{server_IP}} -p 8084 -g 3

status:
    ./f-stack/dpdk/usertools/dpdk-devbind.py --status
