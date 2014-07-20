//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_config_hpp_
#define shinano_config_hpp_

#include <cstddef>
#include <cstdint>
#include <boost/predef/other/endian.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

namespace shinano {

inline constexpr std::uint8_t
reorder(std::uint8_t v) noexcept { return v; }

inline constexpr std::uint16_t
reorder(std::uint16_t v) noexcept { return (v << 8) | (v >> 8); }

inline constexpr std::uint32_t
reorder(std::uint32_t v) noexcept
{
    return  reorder(static_cast<std::uint16_t>(v >> 16))
         | (reorder(static_cast<std::uint16_t>(v      )) << 16);
}

// XXX: Take care of endian by Boost.Predef
template <typename T>
inline constexpr T
host_to_net(T v) noexcept { return reorder(v); }


// Internet Layer -- IPv4
struct ipv4 { // pseudo-namespace

static constexpr auto domain = AF_INET;

typedef ip header;
static constexpr auto header_length = sizeof(header);

typedef sockaddr_in sockaddr;

}; // pseudo-namespace shinano::ipv4


// Internet Layer -- IPv6
struct ipv6 { // pseudo-namespace

static constexpr auto domain = AF_INET6;

typedef ip6_hdr header;
static constexpr auto header_length = sizeof(header);

typedef sockaddr_in6 sockaddr;

}; // pseudo-namespace shinano::ipv6

} // namespace shinano

namespace ieee {

enum class protocol_number : std::uint16_t
{
    ip   = shinano::host_to_net<std::uint16_t>(0x0800),
    ipv6 = shinano::host_to_net<std::uint16_t>(0x86dd),
};

} // namespace ieee

namespace iana {

// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
enum class protocol_number : std::uint8_t
{
    hopopt     = 0,
    icmp       = 1,
    igmp       = 2,
    ipv4       = 4,
    tcp        = 6,
    udp        = 17,
    dccp       = 33,
    ipv6       = 41,
    ipv6_route = 43,
    ipv6_frag  = 44,
    gre        = 47,
    icmp6      = 58,
    ipv6_nonxt = 59,
    ipv6_opts  = 60,
};

} // namespace iana

#endif
