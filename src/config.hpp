//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_config_hpp_
#define shinano_config_hpp_

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <boost/predef/other/endian.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

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

// http://tools.ietf.org/html/rfc792
namespace icmp {

// ICMP message type
enum class type : std::uint8_t
{
    destination_unreachable = 3,
    time_exceeded = 11,
    parameter_problem = 12,
    source_quench = 4,
    redirect = 5,

    echo_request = 8,
    echo_reply = 0,

    timestamp_request = 13,
    timestamp_reply = 14,

    information_request = 15,
    information_reply = 16,
};


} // namespace iana::icmp

using icmp_type [[gnu::deprecated("use iana::icmp::type")]] = icmp::type;


// http://tools.ietf.org/html/rfc4443
namespace icmp6 {

// ICMPv6 message type
enum class type : std::uint8_t
{
    // From 1 to 127 show error message.
    destination_unreachable = 1,
    packet_too_big = 2,
    time_exceeded = 3,
    parameter_problem = 4,

    experimentation_error_1 = 100,
    experimentation_error_2 = 101,

    reserved_for_error = 127,

    // From 128 to 255 show informational message.
    echo_request = 128,
    echo_reply = 129,

    experimentation_informational_1 = 200,
    experimentation_informational_2 = 201,

    reserved_for_informational = 255,
};

} // namespace iana::icmp6

using icmp6_type [[gnu::deprecated("use iana::icmp6::type")]] = icmp6::type;

} // namespace iana

#endif
