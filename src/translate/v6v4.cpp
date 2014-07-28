//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>

#include "config.hpp"
#include "util.hpp"
#include "detail/designated_initializer.hpp"

#include "translate.hpp"
#include "translate/address_table.hpp"

#include <algorithm>

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

// return complement of checksum
std::uint16_t
icmp_ccs(const iovec &h, const iovec &pl)
{
    using word = std::uint16_t;

    word sum = 0;

    auto reducer = [](word a, word v)
    {
        auto x = a + net_to_host(v);
        return x + (x >> 16);
    };

    {
        auto b = reinterpret_cast<const word *>(h.iov_base);
        sum = std::accumulate(b, b + (h.iov_len / 2), sum, reducer);
    }

    {
        auto b = reinterpret_cast<const word *>(pl.iov_base);
        auto e = b + (pl.iov_len / 2);
        sum = std::accumulate(b, e, sum, reducer);

        if (pl.iov_len % 2)
        {
            auto odd = *reinterpret_cast<const std::uint8_t *>(e) << 8;
            sum = reducer(sum, odd);
        }
    }

    return host_to_net(sum);
}

void
icmp6(raw &fwd, const input_buffer &b, const in_addr &src, const in_addr &dst)
{
    auto &iphdr = b.internet_header<ipv6>();
    auto icmp6 = static_cast<const ipv6::icmp6_header *>(b.next_to_ip<ipv6>());

    iovec outbound[3];
    const auto addr = designated((sockaddr_in)) by
    (
      ((.sin_family = AF_INET))
      ((.sin_addr   = dst))
    );

    auto outbound_ip = designated((ipv4::header)) by
    (
      ((.ip_v   = 4))
      ((.ip_hl  = sizeof(ipv4::header) / 4)) // have no option
      //((.ip_tos = <<unspecified>>))
      //((.ip_len = <<TBD>>)) // XXX: or does kernel fill this field?
      //((.ip_id  = <<unspecified>>)) // kernel fill this field iff 0
      ((.ip_off = 0)) // fragment is not supported currently
      ((.ip_ttl = iphdr.ip6_hlim - 1))
      ((.ip_p   = static_cast<std::uint8_t>(iana::protocol_number::icmp)))
      //((.ip_sum = <<unspecified>>)) // kernel always calc checksum
      ((.ip_src = src))
      ((.ip_dst = dst))
    );
    outbound[0].iov_base = &outbound_ip;
    outbound[0].iov_len  = sizeof(outbound_ip);

    auto outbound_icmp = designated((ipv4::icmp_header)) by ( );
    outbound[1].iov_base = &outbound_icmp;
    outbound[1].iov_len = sizeof(outbound_icmp);

    switch (static_cast<iana::icmp6_type>(icmp6->icmp6_type))
    {
      case iana::icmp6_type::echo_request:
        temporary_show_detail("icmp6 echo req", "icmp echo req", iphdr, src, dst);
        outbound_icmp.type = static_cast<std::uint8_t>(iana::icmp_type::echo_request);
        outbound[1].iov_len = 4;
        outbound[2].iov_base = const_cast<void *>(b.next_to_ip<ipv6>(outbound[1].iov_len));
        outbound[2].iov_len = net_to_host(iphdr.ip6_plen) - length(iphdr) - outbound[1].iov_len;
        break;

      case iana::icmp6_type::echo_reply:
        temporary_show_detail("icmp6 echo rep", "icmp echo rep", iphdr, src, dst);
        outbound_icmp.type = static_cast<std::uint8_t>(iana::icmp_type::echo_reply);
        outbound[1].iov_len = 4;
        outbound[2].iov_base = const_cast<void *>(b.next_to_ip<ipv6>(outbound[1].iov_len));
        outbound[2].iov_len = net_to_host(iphdr.ip6_plen) - length(iphdr) - outbound[1].iov_len;
        break;

      default:
        temporary_show_detail("icmp6", "icmp", iphdr, src, dst);
        return;
    }

    outbound_icmp.checksum = ~icmp_ccs(outbound[1], outbound[2]);
    fwd.sendmsg(outbound, addr);
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
