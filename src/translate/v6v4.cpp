//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>

#include "config.hpp"
#include "util.hpp"
#include "translate.hpp"

namespace {

template <typename T>
using wrap = std::reference_wrapper<T>;

} // <anonymous-namespace>

namespace shinano {

// v6 to v4
template <>
bool
translate<ipv4>(wrap<raw> fwd, wrap<input_buffer> b) try
{
    auto iphdr = b.get().internet_header<ipv6>();

    BOOST_ASSERT((iphdr->ip6_vfc >> 4) == 6);

    switch (payload_protocol(*iphdr))
    {
      case iana::protocol_number::icmp6:
        std::cout << "[icmp6] "
          << to_string(source(*iphdr)) << " -> " << to_string(dest(*iphdr))
          << " / " << b.get().size() << " bytes"
          << std::endl;
        break;

      default:
        // drop unsupported packet
        return false;
    }

    return true;
}
catch (translate_error &e)
{
    std::cerr << e.what() << std::endl;
    return true;
}

} // namespace shinano
