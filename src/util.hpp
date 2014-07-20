//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_util_hpp_
#define shinano_util_hpp_

#include <string>
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


inline constexpr iana::protocol_number
payload_protocol(const ip &hdr) noexcept
{ return static_cast<iana::protocol_number>(hdr.ip_p); }

inline constexpr iana::protocol_number
payload_protocol(const ip6_hdr &hdr) noexcept
{ return static_cast<iana::protocol_number>(hdr.ip6_nxt); }


} // namespace shinano

#endif
