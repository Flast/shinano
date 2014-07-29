//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>
#include <cstdint>

#include "config.hpp"
#include "util.hpp"
#include "detail/designated_initializer.hpp"

#include "translate.hpp"
#include "translate/address_table.hpp"
#include "translate/checksum.hpp"

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
icmp6(raw &fwd, const input_buffer &b, const in_addr &src, const in_addr &dst)
{
    auto &iphdr = b.internet_header<ipv6>();
    auto icmp6 = static_cast<const ipv6::icmp6_header *>(b.next_to_ip<ipv6>());

    iovec ob[3];
    const auto addr = designated((sockaddr_in)) by
    (
      ((.sin_family = AF_INET))
      ((.sin_addr   = dst))
    );

    auto ob_ip = designated((ipv4::header)) by
    (
      ((.ip_v   = 4))
      ((.ip_hl  = sizeof(ipv4::header) / 4)) // have no option
      //((.ip_tos = <<unspecified>>))
      //((.ip_len = <<TBD>>)) // kernel fill this field iff 0
      //((.ip_id  = <<unspecified>>)) // kernel fill this field iff 0
      ((.ip_off = 0)) // fragment is not supported currently
      ((.ip_ttl = iphdr.ip6_hlim - 1))
      ((.ip_p   = static_cast<std::uint8_t>(iana::protocol_number::icmp)))
      //((.ip_sum = <<unspecified>>)) // kernel always calc checksum
      ((.ip_src = src))
      ((.ip_dst = dst))
    );
    ob[0].iov_base = &ob_ip;
    ob[0].iov_len  = sizeof(ob_ip);

    auto ob_icmp   = designated((ipv4::icmp_header)) by ( );
    ob[1].iov_base = &ob_icmp;
    ob[1].iov_len  = sizeof(ob_icmp);

    switch (static_cast<iana::icmp6_type>(icmp6->icmp6_type))
    {
      case iana::icmp6_type::echo_request:
        temporary_show_detail("icmp6 echo req", "icmp echo req", iphdr, src, dst);
        ob_icmp.type   = static_cast<std::uint8_t>(iana::icmp_type::echo_request);
        ob[1].iov_len  = 4;
        ob[2].iov_base = const_cast<void *>(b.next_to_ip<ipv6>(ob[1].iov_len));
        ob[2].iov_len  = plength(iphdr) - ob[1].iov_len;
        break;

      case iana::icmp6_type::echo_reply:
        temporary_show_detail("icmp6 echo rep", "icmp echo rep", iphdr, src, dst);
        ob_icmp.type   = static_cast<std::uint8_t>(iana::icmp_type::echo_reply);
        ob[1].iov_len  = 4;
        ob[2].iov_base = const_cast<void *>(b.next_to_ip<ipv6>(ob[1].iov_len));
        ob[2].iov_len  = plength(iphdr) - ob[1].iov_len;
        break;

      default:
        temporary_show_detail("icmp6", "icmp", iphdr, src, dst);
        return;
    }

    ob_icmp.checksum = ~detail::ccs(ob[1], ob[2]);
    fwd.sendmsg(ob, addr);
}

} // namespace shinano::<anonymous-namespace>

// v6 to v4
template <>
bool
translate<ipv4>(wrap<raw> fwd, wrap<input_buffer> b) try
{
    auto &iphdr = b.get().internet_header<ipv6>();

    BOOST_ASSERT((iphdr.ip6_vfc >> 4) == 6);
    // TODO: should check hop limit (aka TTL)

    auto srcv4 = lookup(source(iphdr));
    auto dstv4 = extract_embedded_address(dest(iphdr), temporary_prefix(), temporary_plen());

    switch (payload_protocol(iphdr))
    {
      case iana::protocol_number::icmp6:
        icmp6(fwd, b, srcv4, dstv4);
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
