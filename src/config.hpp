//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_config_hpp_
#define shinano_config_hpp_

#include <cstddef>
#include <cstdint>
#include <chrono>
//#include <boost/predef/other/endian.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "config/iana.hpp"

namespace shinano {

namespace config {

constexpr int max_backtrace_count = 20;

constexpr std::chrono::seconds table_expires_after {1800};

} // namespace shinano::config

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

// XXX: Take care of endian by Boost.Predef
template <typename T>
inline constexpr T
net_to_host(T v) noexcept { return reorder(v); }


// Internet Layer -- IPv4
struct ipv4 { // pseudo-namespace

static constexpr auto domain = AF_INET;

typedef ip      header;
typedef icmphdr icmp_header;

typedef sockaddr_in sockaddr;

struct pseudo_header
{
    in_addr       pip_src;
    in_addr       pip_dst;
    std::uint8_t  _pip_padding;
    std::uint8_t  pip_proto;
    std::uint16_t pip_len;
};

}; // pseudo-namespace shinano::ipv4


// Internet Layer -- IPv6
struct ipv6 { // pseudo-namespace

static constexpr auto domain = AF_INET6;

typedef ip6_hdr   header;
typedef icmp6_hdr icmp6_header;

struct pseudo_header
{
    in6_addr      pip6_src;
    in6_addr      pip6_dst;
    std::uint32_t pip6_plen;
    std::uint8_t  _pip6_padding[3];
    std::uint8_t  pip6_nxt;
};

typedef sockaddr_in6 sockaddr;

}; // pseudo-namespace shinano::ipv6

namespace tag {

struct icmp  { typedef icmphdr   header; };
struct icmp6 { typedef icmp6_hdr header; };
struct tcp   { typedef tcphdr    header; };
struct udp   { typedef udphdr    header; };

} // namespace shinano:;tag

} // namespace shinano

namespace ieee {

enum class protocol_number : std::uint16_t
{
    ip   = shinano::host_to_net<std::uint16_t>(0x0800),
    ipv6 = shinano::host_to_net<std::uint16_t>(0x86dd),
};

} // namespace ieee

#endif
