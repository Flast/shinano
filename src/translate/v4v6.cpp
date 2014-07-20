//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>

#include "util.hpp"
#include "translate.hpp"

namespace shinano {

namespace {

template <typename T>
using wrap = std::reference_wrapper<T>;

} // shinano::<anonymous-namespace>

// v4 to v6
template <>
void
translate<ipv6>(wrap<tuntap> fwd, wrap<input_buffer> b)
{
    auto iphdr = b.get().internet_header<ipv4>();

    BOOST_ASSERT(iphdr->ip_v == 4);

    std::cout << "[IPv4] "
      << to_string(source(*iphdr)) << " -> " << to_string(dest(*iphdr))
      << " / " << b.get().size() << " bytes"
      << std::endl;
}

} // namespace shinano
