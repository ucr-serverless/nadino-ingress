# Justfile
# a just file for development only

bear:
    bear -- make build

make:
    bash ./configure --prefix=/usr/local/nginx_fstack --with-ff_module --with-debug

clean:
    make clean

kill:
    sudo pkill -i nginx

run:
    sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"

log:
    sudo cat /var/log/syslog | grep "f-stack"

install:
    sudo make install

fs:
    export FF_PATH=~/palladium-ingress/f-stack
    export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
    cd f-stack/lib/
    make -j -C f-stack/lib/
    sudo make -C f-stack/lib/ install
    cd ../..

rdma:
    make -C ./RDMA_lib/

init:
    sed -i 's\https://github.com/ucr-serverless/RDMA_lib.git\git@github.com:ucr-serverless/RDMA_lib.git\g' .gitmodules
    git submodule update --init --recursive
    cd RDMA_lib && git checkout main
