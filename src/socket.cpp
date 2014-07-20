//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <string>
#include <cstring>

#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include "socket.hpp"

#include "detail/designated_initializer.hpp"

namespace shinano {

controle_socket::controle_socket()
  : safe_desc(::socket(AF_PACKET, SOCK_PACKET, 0))
{
}

tuntap::tuntap(int flags, std::string name)
  : safe_desc(::open("/dev/net/tun", O_RDWR))
{
    auto ifr = designated((ifreq)) by
    (
      ((.ifr_flags = flags))
    );
    std::strncpy(ifr.ifr_name, name.c_str(), sizeof(ifr.ifr_name));
    ioctl(TUNSETIFF, &ifr);

    controle_socket cs;
    cs.ioctl(SIOCGIFINDEX, &ifr);
    index = ifr.ifr_ifindex;
}

tuntap::tuntap(tap_tag, std::string name)
  : tuntap(IFF_TAP, name) { }
tuntap::tuntap(tun_tag, std::string name)
  : tuntap(IFF_TUN, name) { }

void
tuntap::up(bool up)
{
    controle_socket cs;
    auto ifr = designated((ifreq)) by
    (
      ((.ifr_ifindex = index))
    );
    cs.ioctl(SIOCGIFNAME, &ifr);

    cs.ioctl(SIOCGIFFLAGS, &ifr);
    if (up) { ifr.ifr_flags |=  IFF_UP; }
    else    { ifr.ifr_flags &= ~IFF_UP; }
    cs.ioctl(SIOCSIFFLAGS, &ifr);
}

} // namespace shinano
