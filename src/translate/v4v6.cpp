//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>
#include <cstdint>

#include "config.hpp"
#include "util.hpp"
#include "detail/designated_initializer.hpp"
#include "detail/exception.hpp"

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

    std::cout
      << "[" << from << "] "
        << to_string(source(iphdr)) << " -> " << to_string(dest(iphdr))
        << std::endl
      << "    TTL " << int(iphdr.ip_ttl) << " / " << payload_length << " bytes"
        << std::endl
      << "    translate to [" << to << "] "
        << to_string(src) << " -> " << to_string(dst)
        << std::endl;
}

void
finalize_icmp6(iovec (&ob)[5]) noexcept
{
    auto &ob_ip6   = *static_cast<ipv6::header *>(ob[0].iov_base);
    auto &ob_icmp6 = *static_cast<ipv6::icmp6_header *>(ob[1].iov_base);

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
}

void
icmp(raw &fwd, buffer_ref b, const in6_addr &src, const in6_addr &dst)
{
    auto &iphdr = b.internet_header<ipv4>();
    const auto icmp = static_cast<const ipv4::icmp_header *>(b.next_to_ip<ipv4>().data());

    // We should treat 5 separated fields in icmp error message.
    //
    //             | icmp6 error message ...
    // ip6 | icmp6 | ip6 | icmp6 | payload ...
    //                v
    //             | icmp error message ...
    // ip  | icmp  | ip  | icmp  | payload ...
    iovec ob[5] = {};
    std::size_t ob_cnt = 3;

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
        ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::echo_request);
        ob[2].iov_base      = b.next_to_ip<ipv4>(ob[1].iov_len).data();
        ob[2].iov_len       = plength(iphdr) - ob[1].iov_len;
        break;

      case iana::icmp_type::echo_reply:
        ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::echo_reply);
        ob[2].iov_base      = b.next_to_ip<ipv4>(ob[1].iov_len).data();
        ob[2].iov_len       = plength(iphdr) - ob[1].iov_len;
        break;

      case iana::icmp_type::timestamp_request:
      case iana::icmp_type::timestamp_reply:
      case iana::icmp_type::information_request:
      case iana::icmp_type::information_reply:
        std::cout << "info: silently dropped: obsoleted in icmp6" << std::endl;
        return;

      case iana::icmp_type::destination_unreachable:
        using iana::icmp6::destination_unreachable;
        ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::destination_unreachable);

        switch (static_cast<iana::icmp::destination_unreachable>(icmp->code))
        {
          case iana::icmp::destination_unreachable::net:
          case iana::icmp::destination_unreachable::host:
          case iana::icmp::destination_unreachable::source_route_failed:
            detail::throw_exception(translate_error("not implemented yet"));
            ob_icmp6.icmp6_code = static_cast<std::uint8_t>(destination_unreachable::no_route_to_destination);

          case iana::icmp::destination_unreachable::protocol:
            detail::throw_exception(translate_error("unsupported ICMP type/code"));
            ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::parameter_problem);
            ob_icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::parameter_problem::header_field);

          case iana::icmp::destination_unreachable::port:
            detail::throw_exception(translate_error("unsupported ICMP type/code"));
            ob_icmp6.icmp6_code = static_cast<std::uint8_t>(destination_unreachable::port);

          case iana::icmp::destination_unreachable::dont_fragment:
            detail::throw_exception(translate_error("not implemented yet"));
            ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::packet_too_big);
            ob_icmp6.icmp6_code = 0;

          default:
            detail::throw_exception(translate_error("unknown ICMP code"));
        };
        break;

      case iana::icmp_type::redirect:
        std::cout << "info: silently dropped" << std::endl;
        return;
      case iana::icmp_type::source_quench:
        std::cout << "info: silently dropped: obsoleted in icmp6" << std::endl;
        return;

      case iana::icmp_type::time_exceeded:
        detail::throw_exception(translate_error("not implemented yet"));
        ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::time_exceeded);
        ob_icmp6.icmp6_code = icmp->code;
        break;

      case iana::icmp_type::parameter_problem:
        detail::throw_exception(translate_error("not implemented yet"));
        ob_icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::parameter_problem);

        switch (static_cast<iana::icmp::parameter_problem>(icmp->code))
        {
          case iana::icmp::parameter_problem::pointer_indicates:
            detail::throw_exception(translate_error("not implemented yet"));
            ob_icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::parameter_problem::header_field);

          default:
            detail::throw_exception(translate_error("unknown ICMP code"));
        }
        break;

      // others; silently drop
      default:
        detail::throw_exception(translate_error("unknown ICMP type"));
    }
    temporary_show_detail("icmp", "icmp6", iphdr, src, dst);

    finalize_icmp6(ob);

    fwd.sendmsg(ob, ob_cnt, designated((sockaddr_in6)) by
    (
      ((.sin6_family = AF_INET6))
      ((.sin6_addr   = dst))
    ));
}

} // shinano::<anonymous-namespace>

// v4 to v6
template <>
bool
translate<ipv6>(wrap<raw> fwd, buffer_ref b) try
{
    auto &iphdr = b.internet_header<ipv4>();

    BOOST_ASSERT(iphdr.ip_v == 4);

    if (iphdr.ip_ttl <= 1)
    {
        // FIXME: Should return icmp time exceeded error message.
        std::cout << "info: time exceeded" << std::endl;
        return true;
    }

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
