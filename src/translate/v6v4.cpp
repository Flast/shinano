//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>

#include "util.hpp"
#include "translate.hpp"

namespace {

template <typename T>
using wrap = std::reference_wrapper<T>;

} // <anonymous-namespace>

namespace shinano {

// v6 to v4
template <>
void
translate<ipv4>(wrap<tuntap> fwd, wrap<input_buffer> b)
{
    auto iphdr = b.get().internet_header<ipv6>();

    BOOST_ASSERT((iphdr->ip6_vfc >> 4) == 6);

    std::cout << "[IPv6] "
      << to_string(source(*iphdr)) << " -> " << to_string(dest(*iphdr))
      << " / " << b.get().size() << " bytes"
      << std::endl;
}

} // namespace shinano
