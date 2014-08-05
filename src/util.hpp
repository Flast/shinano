//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_util_hpp_
#define shinano_util_hpp_

#include <string>
#include <utility>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "config.hpp"

namespace shinano {

std::string
to_string(const in_addr &);

std::string
to_string(const in6_addr &);


inline constexpr       in_addr & source(      ip &hdr) noexcept { return hdr.ip_src; }
inline constexpr const in_addr & source(const ip &hdr) noexcept { return hdr.ip_src; }
inline constexpr       in6_addr & source(      ip6_hdr &hdr) noexcept { return hdr.ip6_src; }
inline constexpr const in6_addr & source(const ip6_hdr &hdr) noexcept { return hdr.ip6_src; }

inline constexpr       in_addr & dest(      ip &hdr) noexcept { return hdr.ip_dst; }
inline constexpr const in_addr & dest(const ip &hdr) noexcept { return hdr.ip_dst; }
inline constexpr       in6_addr & dest(      ip6_hdr &hdr) noexcept { return hdr.ip6_dst; }
inline constexpr const in6_addr & dest(const ip6_hdr &hdr) noexcept { return hdr.ip6_dst; }


// header length
inline constexpr std::size_t length(const ip        &hdr) noexcept { return hdr.ip_hl * 4; }
inline constexpr std::size_t length(const ip6_hdr   &hdr) noexcept { return sizeof(ip6_hdr); }
inline constexpr std::size_t length(const icmphdr   &hdr) noexcept { return 8; }
inline constexpr std::size_t length(const icmp6_hdr &hdr) noexcept { return 8; }

template <typename T>
inline constexpr std::size_t length(const T &v) noexcept { return sizeof(T); }

// payload length
inline constexpr std::size_t plength(const ip      &hdr) noexcept
{ return net_to_host(hdr.ip_len) - length(hdr); }
inline constexpr std::size_t plength(const ip6_hdr &hdr) noexcept
{ return net_to_host(hdr.ip6_plen); }


inline constexpr iana::protocol_number
payload_protocol(const ip &hdr) noexcept
{ return static_cast<iana::protocol_number>(hdr.ip_p); }

inline constexpr iana::protocol_number
payload_protocol(const ip6_hdr &hdr) noexcept
{ return static_cast<iana::protocol_number>(hdr.ip6_nxt); }


in_addr
extract_embedded_address(const in6_addr &embed, const in6_addr &prefix, std::size_t plen);

in6_addr
make_embedded_address(const in_addr &x, const in6_addr &prefix, std::size_t plen);


template <int D, typename A, int N>
inline constexpr typename std::enable_if<(N > D), A(&)[N - D]>::type
drop(A (&a)[N]) noexcept
{
    return *reinterpret_cast<A(*)[N - D]>(a + D);
}

} // namespace shinano

#endif
