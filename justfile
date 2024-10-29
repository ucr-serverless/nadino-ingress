# Justfile
# a just file for development only

bear:
    bear -- make

make:
    make clean
    bash ./configure --prefix=/usr/local/nginx_fstack --with-ff_module

kill:
    sudo pkill -i nginx
