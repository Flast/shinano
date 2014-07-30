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
icmp(raw &fwd, const input_buffer &b, const in6_addr &src, const in6_addr &dst)
{
    auto &iphdr = b.internet_header<ipv4>();
    const auto icmp = static_cast<const ipv4::icmp_header *>(b.next_to_ip<ipv4>());

    iovec ob[3];
    const auto addr = designated((sockaddr_in6)) by
    (
      ((.sin6_family = AF_INET6))
      ((.sin6_addr   = dst))
    );

    auto ob_ip6 = designated((ipv6::header)) by
    (
      ((.ip6_vfc  = (6 << 4)))
      //((.ip6_flow = <<unspecified>>))
      //((.ip6_plen = <<TBD>>)) // kernel doesn't calc this field unlike ipv4.
      ((.ip6_nxt  = static_cast<std::uint8_t>(iana::protocol_number::icmp6)))
      ((.ip6_hlim = iphdr.ip_ttl - 1))
      ((.ip6_src  = src))
      ((.ip6_dst  = dst))
    );
    ob[0].iov_base = &ob_ip6;
    ob[0].iov_len  = sizeof(ob_ip6);

    auto ob_icmp6  = designated((ipv6::icmp6_header)) by ( );
    ob[1].iov_base = &ob_icmp6;
    ob[1].iov_len  = 4;

    // http://tools.ietf.org/html/rfc6145#section-4.2
    // http://tools.ietf.org/html/rfc6145#section-4.3
    switch (static_cast<iana::icmp_type>(icmp->type))
    {
      case iana::icmp_type::echo_request:
        temporary_show_detail("icmp echo req", "icmp6 echo req", iphdr, src, dst);
        ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::echo_request);
        ob[2].iov_base      = const_cast<void *>(b.next_to_ip<ipv4>(ob[1].iov_len));
        ob[2].iov_len       = plength(iphdr) - ob[1].iov_len;
        break;

      case iana::icmp_type::echo_reply:
        temporary_show_detail("icmp echo rep", "icmp6 echo rep", iphdr, src, dst);
        ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::echo_reply);
        ob[2].iov_base      = const_cast<void *>(b.next_to_ip<ipv4>(ob[1].iov_len));
        ob[2].iov_len       = plength(iphdr) - ob[1].iov_len;
        break;

      // others; silently drop
      default:
        temporary_show_detail("icmp", "icmp6", iphdr, src, dst);
        return;
    }

    ob_ip6.ip6_plen = host_to_net<std::uint16_t>(ob[1].iov_len + ob[2].iov_len);

    const auto ph = designated((ipv6::pseudo_header)) by
    (
      ((.pip6_src  = ob_ip6.ip6_src))
      ((.pip6_dst  = ob_ip6.ip6_dst))
      ((.pip6_plen = ob_ip6.ip6_plen))
      ((.pip6_nxt  = ob_ip6.ip6_nxt))
    );
    const auto phv = designated((iovec)) by
    (
      ((.iov_base = const_cast<void *>(static_cast<const void *>(&ph))))
      ((.iov_len  = sizeof(ph)))
    );

    ob_icmp6.icmp6_cksum = ~detail::ccs(phv, ob[1], ob[2]);
    fwd.sendmsg(ob, addr);
}

} // shinano::<anonymous-namespace>

// v4 to v6
template <>
bool
translate<ipv6>(wrap<raw> fwd, wrap<input_buffer> b) try
{
    auto &iphdr = b.get().internet_header<ipv4>();

    BOOST_ASSERT(iphdr.ip_v == 4);
    // TODO: should check TTL

    auto srcv6 = make_embedded_address(source(iphdr), temporary_prefix(), temporary_plen());
    auto dstv6 = lookup(dest(iphdr));

    switch (payload_protocol(iphdr))
    {
      case iana::protocol_number::icmp:
        icmp(fwd, b, srcv6, dstv6);
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
