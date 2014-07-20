//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

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

} // namespace shinano
