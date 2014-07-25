//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include "detail/exception.hpp"

#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.hpp"

#include <array>
#include <string>

namespace shinano {

std::string
to_string(const in_addr &addr)
{
    std::array<char, INET_ADDRSTRLEN> buf;

    if (inet_ntop(AF_INET, &addr.s_addr, buf.data(), buf.size()) == NULL)
    {
        return {};
    }

    return buf.data();
}

std::string
to_string(const in6_addr &addr)
{
    std::array<char, INET6_ADDRSTRLEN> buf;

    if (inet_ntop(AF_INET6, &addr.s6_addr, buf.data(), buf.size()) == NULL)
    {
        return {};
    }

    return buf.data();
}


// The IPv4 embedded v6 address should lie on one of following 8-octet boundary prefixes, see Section 2-2 of RFC6052.
//
//    +------- 32 - 40 - 48 - 56 - 64 - 72 - 80 - 88 - 96 - 104 --+
// 32 | prefix | v4                | r  | suf                     |
// 40 |    prefix   | v4           | r  | v4 | suf                |
// 48 |       prefix     | v4      | r  | v4      | suf           |
// 56 |          prefix       | v4 | r  | v4           | suf      |
// 64 |             prefix         | r  | v4                | suf |
// 96 |                      prefix                    | v4       |
//    +-----------------------------------------------------------+
//
//    NOTE: The `r` field is reserved and should be zero. And the suf(a.k.a suffix)
//          is reserved for future purpose and should be zero. RFC6052 also says the
//          translator should ignore such field even if not zero.

in_addr
extract_embedded_address(const in6_addr &embed, const in6_addr &prefix, std::size_t plen)
{
    in_addr x;

    // TODO: Check that prefix is match.

    switch (plen)
    {
      case 32:
      case 40:
      case 48:
      case 56:
      case 64:
        // TODO: Implement for above prefix length.
        detail::throw_exception(std::runtime_error("foo"));

      case 96:
        // TODO: Take care of byte endian.
        // x.s_addr = embed.s6_addr32[0]; for BIG-endian
        x.s_addr = embed.s6_addr32[3];
        return x;

      default:
        // FIXME: Should throw eligible exception object.
        detail::throw_exception(std::runtime_error("bar"));
    }
}

in6_addr
make_embedded_address(const in_addr &x, const in6_addr &prefix, std::size_t plen)
{
    in6_addr embed = prefix;

    switch (plen)
    {
      case 32:
      case 40:
      case 48:
      case 56:
      case 64:
        // TODO: Implement for above prefix length.
        detail::throw_exception(std::runtime_error("foo"));

      case 96:
        // TODO: Take care of byte endian.
        // embed.s6_addr32[0] = embed.s_addr; for BIG-endian
        embed.s6_addr32[3] = x.s_addr;
        return embed;

      default:
        // FIXME: Should throw eligible exception object.
        detail::throw_exception(std::runtime_error("bar"));
    }
}

} // namespace shinano
