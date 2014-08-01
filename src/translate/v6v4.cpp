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
                      const ipv6::header &iphdr, const in_addr &src, const in_addr &dst)
{
    const auto payload_length = net_to_host(iphdr.ip6_plen);

    std::cout
      << "[" << from << "] "
        << to_string(source(iphdr)) << " -> " << to_string(dest(iphdr))
        << std::endl
      << "    Hop limit " << int(iphdr.ip6_hlim) << " / " << payload_length << " bytes"
        << std::endl
      << "    translate to [" << to << "] "
        << to_string(src) << " -> " << to_string(dst)
        << std::endl;
}

void
icmp6(raw &fwd, buffer_ref b, const in_addr &src, const in_addr &dst)
{
    auto &iphdr = b.internet_header<ipv6>();
    auto icmp6 = static_cast<const ipv6::icmp6_header *>(b.next_to_ip<ipv6>());

    iovec ob[3] = {};
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
    ob[1].iov_len  = 4;

    // http://tools.ietf.org/html/rfc6145#section-5.2
    // http://tools.ietf.org/html/rfc6145#section-5.2
    switch (static_cast<iana::icmp6_type>(icmp6->icmp6_type))
    {
      // ICMPv6 information message

      case iana::icmp6_type::echo_request:
        ob_icmp.type   = static_cast<std::uint8_t>(iana::icmp_type::echo_request);
        ob[2].iov_base = const_cast<void *>(b.next_to_ip<ipv6>(ob[1].iov_len));
        ob[2].iov_len  = plength(iphdr) - ob[1].iov_len;
        break;

      case iana::icmp6_type::echo_reply:
        ob_icmp.type   = static_cast<std::uint8_t>(iana::icmp_type::echo_reply);
        ob[2].iov_base = const_cast<void *>(b.next_to_ip<ipv6>(ob[1].iov_len));
        ob[2].iov_len  = plength(iphdr) - ob[1].iov_len;
        break;

      // ICMPv6 error message

      case iana::icmp6_type::destination_unreachable:
        using iana::icmp::destination_unreachable;
        ob_icmp.type = static_cast<std::uint8_t>(iana::icmp_type::destination_unreachable);

        switch (static_cast<iana::icmp6::destination_unreachable>(icmp6->icmp6_code))
        {
          case iana::icmp6::destination_unreachable::no_route_to_destination:
          case iana::icmp6::destination_unreachable::beyond_scope_of_source:
          case iana::icmp6::destination_unreachable::address:
            detail::throw_exception(translate_error("not implemented yet"));
            ob_icmp.code = static_cast<std::uint8_t>(destination_unreachable::host);

          case iana::icmp6::destination_unreachable::administratively_prohibited:
            detail::throw_exception(translate_error("not implemented yet"));

          case iana::icmp6::destination_unreachable::port:
            detail::throw_exception(translate_error("not implemented yet"));
            ob_icmp.code = static_cast<std::uint8_t>(destination_unreachable::port);

          default:
            detail::throw_exception(translate_error("unknown ICMPv6 code"));
        }
        break;

      case iana::icmp6_type::packet_too_big:
        detail::throw_exception(translate_error("not implemented yet"));
        ob_icmp.type = static_cast<std::uint8_t>(iana::icmp_type::destination_unreachable);
        ob_icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::fragmentation_needed);

      case iana::icmp6_type::time_exceeded:
        detail::throw_exception(translate_error("not implemented yet"));
        ob_icmp.type = static_cast<std::uint8_t>(iana::icmp_type::time_exceeded);
        ob_icmp.code = icmp6->icmp6_code;

      case iana::icmp6_type::parameter_problem:
        detail::throw_exception(translate_error("not implemented yet"));
        ob_icmp.type = static_cast<std::uint8_t>(iana::icmp_type::parameter_problem);

        switch (static_cast<iana::icmp6::parameter_problem>(icmp6->icmp6_code))
        {
          case iana::icmp6::parameter_problem::header_field:
            detail::throw_exception(translate_error("not implemented yet"));
            ob_icmp.code = static_cast<std::uint8_t>(iana::icmp::parameter_problem::pointer_indicates);

          case iana::icmp6::parameter_problem::next_header:
            detail::throw_exception(translate_error("not implemented yet"));
            ob_icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::protocol);

          default:
            detail::throw_exception(translate_error("unknown ICMPv6 code"));
        }
        break;

      // others; silently drop
      default:
        detail::throw_exception(translate_error("unknown ICMPv6 type"));
    }
    temporary_show_detail("icmp6", "icmp", iphdr, src, dst);

    ob_icmp.checksum = ~detail::ccs(ob[1], ob[2]);
    fwd.sendmsg(ob, addr);
}

} // namespace shinano::<anonymous-namespace>

// v6 to v4
template <>
bool
translate<ipv4>(wrap<raw> fwd, buffer_ref b) try
{
    auto &iphdr = b.internet_header<ipv6>();

    BOOST_ASSERT((iphdr.ip6_vfc >> 4) == 6);

    if (iphdr.ip6_hlim <= 1)
    {
        // FIXME: Should return icmp6 time exceeded error message.
        std::cout << "info: time exceeded" << std::endl;
        return true;
    }

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
