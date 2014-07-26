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
                      const ipv4::header &iphdr, const in6_addr &src, const in6_addr &dst)
{
    const auto payload_length = net_to_host(iphdr.ip_len) - length(iphdr);

    std::cout << "[" << from << "] "
      << to_string(source(iphdr)) << " -> " << to_string(dest(iphdr))
      << " / " << payload_length << " bytes"
      << std::endl
      << "    translate to [" << to << "] "
      << to_string(src) << " -> " << to_string(dst)
      << std::endl;
}

void
icmp(const ipv4::header &iphdr, const in6_addr &src, const in6_addr &dst)
{
    temporary_show_detail("icmp", "icmp6", iphdr, src, dst);
}

} // shinano::<anonymous-namespace>

// v4 to v6
template <>
bool
translate<ipv6>(wrap<tuntap> fwd, wrap<input_buffer> b) try
{
    auto &iphdr = b.get().internet_header<ipv4>();

    BOOST_ASSERT(iphdr.ip_v == 4);

    auto srcv6 = make_embedded_address(source(iphdr), temporary_prefix(), temporary_plen());
    auto dstv6 = lookup(dest(iphdr));

    switch (payload_protocol(iphdr))
    {
      case iana::protocol_number::icmp:
        icmp(iphdr, srcv6, dstv6);
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
