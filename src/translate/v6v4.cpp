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

struct iov_ip
{
    union
    {
        int _;
        ipv4::header      ip;
        ipv4::icmp_header icmp;
    };
    void *      base = &ip;
    std::size_t len  = 0;

    void *      (&iov_base) = base;
    std::size_t (&iov_len)  = len;
};

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

template <int N>
std::size_t
icmp6(iov_ip (&iov)[N], buffer_ref b, const in_addr &src, const in_addr &dst)
{
    auto &ip6   = *b.data_as<ipv6::header>();
    auto bip6   = b.next_to<ipv6::header>();
    auto &icmp6 = *bip6.data_as<ipv6::icmp6_header>();

    iov[0].ip = designated((ipv4::header)) by
    (
      ((.ip_v   = 4))
      ((.ip_hl  = sizeof(ipv4::header) / 4)) // have no option
      //((.ip_tos = <<unspecified>>))
      //((.ip_len = <<TBD>>)) // kernel fill this field iff 0
      //((.ip_id  = <<unspecified>>)) // kernel fill this field iff 0
      ((.ip_off = 0)) // fragment is not supported currently
      ((.ip_ttl = ip6.ip6_hlim))
      ((.ip_p   = static_cast<std::uint8_t>(iana::protocol_number::icmp)))
      //((.ip_sum = <<unspecified>>)) // kernel always calc checksum
      ((.ip_src = src))
      ((.ip_dst = dst))
    );
    iov[0].len = length(iov[0].ip);

    iov[1].icmp.un.gateway = icmp6.icmp6_data32[0];
    iov[1].len = length(iov[1].icmp);

    // for ip, icmp and icmp payload
    std::size_t count = 3;

    // http://tools.ietf.org/html/rfc6145#section-5.2
    // http://tools.ietf.org/html/rfc6145#section-5.2
    switch (static_cast<iana::icmp6_type>(icmp6.icmp6_type))
    {
      // ICMPv6 information message

      case iana::icmp6_type::echo_request:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp_type::echo_request);
        iov[2].base      = bip6.next_to<ipv6::icmp6_header>().data();
        iov[2].len       = plength(ip6) - iov[1].len;
        break;

      case iana::icmp6_type::echo_reply:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp_type::echo_reply);
        iov[2].base      = bip6.next_to<ipv6::icmp6_header>().data();
        iov[2].len       = plength(ip6) - iov[1].len;
        break;

      // ICMPv6 error message

      case iana::icmp6_type::destination_unreachable:
        using iana::icmp::destination_unreachable;
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp_type::destination_unreachable);

        switch (static_cast<iana::icmp6::destination_unreachable>(icmp6.icmp6_code))
        {
          case iana::icmp6::destination_unreachable::no_route_to_destination:
          case iana::icmp6::destination_unreachable::beyond_scope_of_source:
          case iana::icmp6::destination_unreachable::address:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp.code = static_cast<std::uint8_t>(destination_unreachable::host);

          case iana::icmp6::destination_unreachable::administratively_prohibited:
            detail::throw_exception(translate_error("not implemented yet"));

          case iana::icmp6::destination_unreachable::port:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp.code = static_cast<std::uint8_t>(destination_unreachable::port);

          default:
            detail::throw_exception(translate_error("unknown ICMPv6 code"));
        }
        break;

      case iana::icmp6_type::packet_too_big:
        detail::throw_exception(translate_error("not implemented yet"));
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp_type::destination_unreachable);
        iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::fragmentation_needed);

      case iana::icmp6_type::time_exceeded:
        detail::throw_exception(translate_error("not implemented yet"));
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp_type::time_exceeded);
        iov[1].icmp.code = icmp6.icmp6_code;

      case iana::icmp6_type::parameter_problem:
        detail::throw_exception(translate_error("not implemented yet"));
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp_type::parameter_problem);

        switch (static_cast<iana::icmp6::parameter_problem>(icmp6.icmp6_code))
        {
          case iana::icmp6::parameter_problem::header_field:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::parameter_problem::pointer_indicates);

          case iana::icmp6::parameter_problem::next_header:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::protocol);

          default:
            detail::throw_exception(translate_error("unknown ICMPv6 code"));
        }
        break;

      // others; silently drop
      default:
        detail::throw_exception(translate_error("unknown ICMPv6 type"));
    }

    iov[1].icmp.checksum = ~detail::i_ccs<1>(iov);
    temporary_show_detail("icmp6", "icmp", ip6, src, dst);

    return count;
}

template <int N>
std::size_t
core(iov_ip (&iov)[N], buffer_ref b, const in_addr &src, const in_addr &dst)
{
    auto &ip = *b.data_as<ipv6::header>();

    switch (payload_protocol(ip))
    {
      case iana::protocol_number::icmp6:
        return icmp6(iov, b, src, dst);
    }

    translate_break("drop unsupported packet", false);
}

} // namespace shinano::<anonymous-namespace>

// v6 to v4
template <>
bool
translate<ipv4>(wrap<raw> fwd, buffer_ref b) try
{
    auto &ip6 = *b.data_as<ipv6::header>();

    BOOST_ASSERT((ip6.ip6_vfc >> 4) == 6);

    if (ip6.ip6_hlim-- <= 1)
    {
        // FIXME: Should return icmp6 time exceeded error message.
        translate_break("time exceeded");
    }

    // We should treat 5 separated fields in icmp error message.
    //
    //             | icmp error message ...
    // ip  | icmp  | ip  | icmp  | payload ...
    //                v
    //             | icmp6 error message ...
    // ip6 | icmp6 | ip6 | icmp6 | payload ...
    constexpr int count = 5;

    iov_ip iov_ip[count] = {};

    auto srcv4 = lookup(source(ip6));
    auto dstv4 = extract_embedded_address(dest(ip6), temporary_prefix(), temporary_plen());

    const auto iov_cnt = core(iov_ip, b, srcv4, dstv4);

    iovec iov[count] = {};
    for (std::size_t i = 0; i < count; ++i)
    {
        iov[i].iov_base = iov_ip[i].iov_base;
        iov[i].iov_len  = iov_ip[i].iov_len;
    }

    fwd.get().sendmsg(iov, iov_cnt, designated((sockaddr_in)) by
    (
      ((.sin_family = AF_INET))
      ((.sin_addr   = dstv4))
    ));

    return true;
}
catch (translate_breaked &e)
{
    std::cerr << "info: " << e.what() << std::endl;
    return e.ret();
}
catch (translate_error &e)
{
    std::cerr << e.what() << std::endl;
    return true;
}

} // namespace shinano
