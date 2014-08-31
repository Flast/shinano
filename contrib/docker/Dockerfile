from fedora:20
user root
workdir /root

run yum -y upgrade ;\
    yum -y install gcc-c++ git \
           make libtool automake autoconf-archive ;\
    yum clean all

run git clone https://github.com/boostorg/boost.git -b develop --recursive --depth 1 ;\
    ( cd boost ;\
      git remote add flast https://github.com/Flast/boost.git ;\
      git fetch flast --depth 1 ;\
      git checkout flast/develop ;\
      git submodule update --init ;\
      ( cd libs/range ;\
        git remote add flast https://github.com/Flast/range.git ;\
        git fetch flast --depth 1 ;\
        git checkout flast/oven ) ;\
      ./bootstrap.sh ;\
      ./b2 headers ;\
      ./b2 install --without-all ) ;\
    rm -rf boost

add shinano.tar.gz /root/
run ( cd /root/shinano ;\
      libtoolize ;\
      aclocal ;\
      autoheader ;\
      automake -a ;\
      autoconf ;\
      ./configure ;\
      make install ) ;\
    rm -rf /root/shinano

cmd sysctl net.ipv6.conf.all.forwarding=1 ;\
    sysctl net.ipv6.conf.all.proxy_ndp=1 ;\
    ip -6 addr add fe80::1/64 dev eth0 ;\
    ip -6 route add default via fe80::2 dev eth0 ;\
    ip tuntap add nat64 mode tun ;\
    ip link set nat64 up ;\
    ip route add 100.64.0.0/10 dev nat64 ;\
    ip -6 route add 64:ff9b::/96 dev nat64 ;\
    shinano nat64 >> /var/log/shinano.log
