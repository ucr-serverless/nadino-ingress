# Justfile
# a just file for development only

bear:
    bear -- make build

make:
    bash ./configure --prefix=/usr/local/nginx_fstack --with-ff_module

clean:
    make clean

kill:
    sudo pkill -i nginx

run:
    sudo /usr/local/nginx_fstack/sbin/nginx -g "daemon off;"

log:
    sudo cat /var/log/syslog | grep "f-stack"
