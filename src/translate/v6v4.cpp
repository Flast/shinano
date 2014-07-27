//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>

#include "config.hpp"
#include "util.hpp"

#include "translate.hpp"
#include "translate/address_table.hpp"

namespace shinano {

namespace {

template <typename T>
using wrap = std::reference_wrapper<T>;

void
temporary_show_detail(const char *from, const char *to,
                      const ipv6::header &iphdr, const in_addr &src, const in_addr &dst)
{
    const auto payload_length = net_to_host(iphdr.ip6_plen);

    std::cout << "[" << from << "] "
      << to_string(source(iphdr)) << " -> " << to_string(dest(iphdr))
      << " / " << payload_length << " bytes"
      << std::endl
      << "    translate to [" << to << "] "
      << to_string(src) << " -> " << to_string(dst)
      << std::endl;
}

void
icmp6(const ipv6::header &iphdr, const in_addr &src, const in_addr &dst)
{
    temporary_show_detail("icmp6", "icmp", iphdr, src, dst);
}

} // namespace shinano::<anonymous-namespace>

// v6 to v4
template <>
bool
translate<ipv4>(wrap<raw> fwd, wrap<input_buffer> b) try
{
    auto &iphdr = b.get().internet_header<ipv6>();

    BOOST_ASSERT((iphdr.ip6_vfc >> 4) == 6);

    auto srcv4 = lookup(source(iphdr));
    auto dstv4 = extract_embedded_address(dest(iphdr), temporary_prefix(), temporary_plen());

    switch (payload_protocol(iphdr))
    {
      case iana::protocol_number::icmp6:
        icmp6(iphdr, srcv4, dstv4);
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
