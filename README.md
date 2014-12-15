## (Stateless) NAT64 user-mode implementation for Linux

### Author

- Kohei Takahashi <flast@tsukuba.wide.ad.jp>

### Pre-requirements

- C++14 return type deduction ready compiler
  + [GCC](http://gcc.gnu.org/) 4.8 or later
  + [Clang](http://clang.llvm.org/) 3.4 or later
- [Boost C++ libraries](http://www.boost.org/)
- OvenToBoost (a.k.a. Range Extensions)
- Autotools
  + [Autoconf Archive](http://www.gnu.org/software/autoconf-archive/)

### Getting Started

1. Clone Boost development branch

    ```
    git clone -b develop --recursive https://github.com/boostorg/boost.git
    ```
  + Note: `develop` branch is *strongly* recommended.
2. Apply OvenToBoost

    ```
    cd boost/libs/range
    git fetch https://github.com/Flast/range.git refs/heads/oven
    git merge FETCH_HEAD
    ```
3. Build Boost

    ```
    cd boost
    ./bootstrap/sh --with-libraries=chrono,system
    ./b2 headers
    ./b2
    ./b2 install --prefix=/path/to # if desired
    ```
  + Note: Installing Boost is unnecessary but *strongly* recommended to lookup .so correctly.
4. Clone `shinano`

    ```
    git clone -b develop https://github.com/Flast/shinano.git
    ```
  + Note: `develop` branch is *strongly* recommended.
5. Configure and make

    ```
    cd shinano
    libtoolize
    aclocal
    autoheader
    automake -a --foreign
    autoconf
    ./configure CPPFLAGS=-I/path/to/boost LDFLAGS=-L/path/to/boost/stage/lib
    ```
6. Run

    ```
    sudo firewall-cmd --zone external --change-interface <eth-if-name> # to NAPT44 be enabled
    sudo ip tuntap add dev <tun-if-name> mode tun
    sudo ip link set <tun-if-name> up
    sudo ip -4 route add 100.64.0.0/10 dev <tun-if-name>
    sudo ip -6 route add 64:ff9b::/96 dev <tun-if-name>
    sudo ./src/shinano <tun-if-name>
    ```

### References

- [RFC2765][2765] - Stateless IP/ICMP Translation Algorithm (SIIT)
  + obsoleted by: [RFC6145][6145]
- [RFC5382][5382] - NAT Behavioral Requirements for TCP
- [RFC6052][6052] - IPv6 Addressing of IPv4/IPv6 Translators
  + references: [RFC1918][1918], [RFC5735 - Section 3][5735-s3]
- [RFC6144][6144] - Framework for IPv4/IPv6 Translation
- [RFC6145][6145] - IP/ICMP Translation Algorithm
  + updated by: [RFC6791][6791]
  + references: [RFC4966][4966]
- [RFC6146][6146] - Stateful NAT64: Network Address and Protocol Translation from IPv6 Clients to IPv4 Servers
- [RFC6791][6791] - Stateless Source Address Mapping for ICMPv6 Packets

  [1918]: http://tools.ietf.org/html/rfc1918
  [2765]: http://tools.ietf.org/html/rfc2765
  [4966]: http://tools.ietf.org/html/rfc4966
  [5382]: http://tools.ietf.org/html/rfc5382
  [5735-s3]: http://tools.ietf.org/html/rfc5735#section-3
  [6052]: http://tools.ietf.org/html/rfc6052
  [6144]: http://tools.ietf.org/html/rfc6144
  [6145]: http://tools.ietf.org/html/rfc6145
  [6146]: http://tools.ietf.org/html/rfc6146
  [6791]: http://tools.ietf.org/html/rfc6791

### License

              Copyright Kohei Takahashi 2014
     Distributed under the Boost Software License, Version 1.0.
        (See accompanying file LICENSE_1_0.txt or copy at
              http://www.boost.org/LICENSE_1_0.txt)

