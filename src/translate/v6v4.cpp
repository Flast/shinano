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
#include "translate/core.hpp"
#include "translate/bib.hpp"
#include "translate/checksum.hpp"

#include <boost/chrono/system_clocks.hpp>
#include <boost/chrono/io/time_point_io.hpp>

namespace shinano {

namespace {

using detail::iov_ip;
using boost::mpl::true_;
using boost::mpl::false_;


template <int N, typename Inner>
std::size_t
core(iov_ip (&iov)[N], buffer_ref b, const in_addr &src, const in_addr &dst, Inner);


template <int N>
inline std::size_t
dispatch_core(iov_ip (&iov)[N], buffer_ref b, const in_addr &src, const in_addr &dst, false_)
{
    return core(iov, b, src, dst, true_{});
}

template <int N>
inline std::size_t
dispatch_core(iov_ip (&iov)[N], buffer_ref b, const in_addr &src, const in_addr &dst, true_)
{
    detail::throw_exception(
        translate_error("ICMPv6 error message containts ICMPv6 error message"));
}

void
temporary_show_detail(const char *from, const char *to,
                      const ipv6::header &iphdr, const in_addr &src, const in_addr &dst)
{
    const auto payload_length = net_to_host(iphdr.ip6_plen);

    const auto now = boost::chrono::system_clock::now();
    std::cout
      << now << ": [" << from << "] " << std::endl
      << "  " << to_string(source(iphdr)) << " -> " << to_string(dest(iphdr))
        << std::endl
      << "    Hop limit " << int(iphdr.ip6_hlim) << " / " << payload_length << " bytes"
        << std::endl
      << "    translate to [" << to << "] "
        << to_string(src) << " -> " << to_string(dst)
        << std::endl;
}


namespace error {

void
sendback_time_exceeded(raw &error, buffer_ref b)
{
    if (payload_protocol(*b.data_as<ipv6::header>()) == iana::protocol_number::icmp6)
    {
        const auto icmp = b.next_to<ipv6::header>().data_as<ipv6::icmp6_header>();
        if (iana::icmp6::is_error(static_cast<iana::icmp6::type>(icmp->icmp6_type)))
        {
            detail::throw_exception(
                translate_error("Time exceeded with ICMPv6 error message"));
        }
    }

    auto icmp6 = designated((ipv6::icmp6_header)) by
    (
      ((.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::time_exceeded)))
      ((.icmp6_code = 0))
    );

    const iovec iov[] = {
      designated((iovec)) by
      (
        ((.iov_base = &icmp6))
        ((.iov_len  = sizeof(icmp6)))
      ),
      designated((iovec)) by
      (
        ((.iov_base = b.data()))
        ((.iov_len  = b.size()))
      )
    };

    const auto dst = source(*b.data_as<ipv6::header>());
    detail::sendmsg(error, iov, designated((sockaddr_in6)) by
    (
      ((.sin6_family = ipv6::domain))
      ((.sin6_addr   = dst))
    ));
}

} // namespace shinano::<anonymous-namespace>::error


template <int N, typename Inner>
std::size_t
reassemble_icmp6_error_body(iov_ip (&iov)[N], buffer_ref b, Inner)
{
    auto be6 = b.next_to<ipv6::icmp6_header>();
    auto &ip6 = *be6.data_as<ipv6::header>();
    auto srcv4 = extract_embedded_address(source(ip6), temporary_prefix(), temporary_plen());
    auto dstv4 = lookup(dest(ip6));
    return dispatch_core(iov, be6, srcv4, dstv4, Inner{});
}

template <int N, typename Inner>
std::size_t
icmp6(iov_ip (&iov)[N], buffer_ref b, Inner)
{
    auto &ip6   = *b.data_as<ipv6::header>();
    auto bip6   = b.next_to<ipv6::header>();
    auto &icmp6 = *bip6.data_as<ipv6::icmp6_header>();

    iov[1].icmp.un.gateway = icmp6.icmp6_data32[0];
    iov[1].len = length(iov[1].icmp);

    // for ip, icmp and icmp payload
    std::size_t count = 3;

    // http://tools.ietf.org/html/rfc6145#section-5.2
    // http://tools.ietf.org/html/rfc6145#section-5.2
    switch (static_cast<iana::icmp6::type>(icmp6.icmp6_type))
    {
      // ICMPv6 information message

      case iana::icmp6::type::echo_request:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp::type::echo_request);
        iov[2].base      = bip6.next_to<ipv6::icmp6_header>().data();
        iov[2].len       = plength(ip6) - iov[1].len;
        break;

      case iana::icmp6::type::echo_reply:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp::type::echo_reply);
        iov[2].base      = bip6.next_to<ipv6::icmp6_header>().data();
        iov[2].len       = plength(ip6) - iov[1].len;
        break;

      // ICMPv6 error message

      case iana::icmp6::type::destination_unreachable:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp::type::destination_unreachable);

        switch (static_cast<iana::icmp6::destination_unreachable>(icmp6.icmp6_code))
        {
          case iana::icmp6::destination_unreachable::no_route_to_destination:
          case iana::icmp6::destination_unreachable::beyond_scope_of_source:
          case iana::icmp6::destination_unreachable::address:
            iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::host);
            count = count - 1 + reassemble_icmp6_error_body(drop<2>(iov), bip6, Inner{});
            break;

          case iana::icmp6::destination_unreachable::administratively_prohibited:
            iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::host_is_a14y_prohibited);
            count = count - 1 + reassemble_icmp6_error_body(drop<2>(iov), bip6, Inner{});
            break;

          case iana::icmp6::destination_unreachable::port:
            iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::port);
            count = count - 1 + reassemble_icmp6_error_body(drop<2>(iov), bip6, Inner{});
            break;

          default:
            detail::throw_exception(translate_error("unknown ICMPv6 code"));
        }
        break;

      case iana::icmp6::type::packet_too_big:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp::type::destination_unreachable);
        iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::fragmentation_needed);
        count = count - 1 + reassemble_icmp6_error_body(drop<2>(iov), bip6, Inner{});
        break;

      case iana::icmp6::type::time_exceeded:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp::type::time_exceeded);
        iov[1].icmp.code = icmp6.icmp6_code;
        count = count - 1 + reassemble_icmp6_error_body(drop<2>(iov), bip6, Inner{});
        break;

      case iana::icmp6::type::parameter_problem:
        iov[1].icmp.type = static_cast<std::uint8_t>(iana::icmp::type::parameter_problem);

        switch (static_cast<iana::icmp6::parameter_problem>(icmp6.icmp6_code))
        {
          case iana::icmp6::parameter_problem::header_field:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::parameter_problem::pointer_indicates);
          // NOTE: Quote from RFC6145
          // Code 0 (Erroneous header field encountered):  Set to Type 12,
          //    Code 0, and update the pointer as defined in Figure 6.  (If
          //    the Original IPv6 Pointer Value is not listed or the
          //    Translated IPv4 Pointer Value is listed as "n/a", silently
          //    drop the packet.)
          //
          //    +--------------------------------+--------------------------------+
          //    |   Original IPv6 Pointer Value  | Translated IPv4 Pointer Value  |
          //    +--------------------------------+--------------------------------+
          //    |  0  | Version/Traffic Class    |  0  | Version/IHL, Type Of Ser |
          //    |  1  | Traffic Class/Flow Label |  1  | Type Of Service          |
          //    | 2,3 | Flow Label               | n/a |                          |
          //    | 4,5 | Payload Length           |  2  | Total Length             |
          //    |  6  | Next Header              |  9  | Protocol                 |
          //    |  7  | Hop Limit                |  8  | Time to Live             |
          //    | 8-23| Source Address           | 12  | Source Address           |
          //    |24-39| Destination Address      | 16  | Destination Address      |
          //    +--------------------------------+--------------------------------+
          //
          //            Figure 6: Pointer Value for Translating from IPv6 to IPv4

          case iana::icmp6::parameter_problem::next_header:
            iov[1].icmp.code = static_cast<std::uint8_t>(iana::icmp::destination_unreachable::protocol);
            count = count - 1 + reassemble_icmp6_error_body(drop<2>(iov), bip6, Inner{});
            break;

          case iana::icmp6::parameter_problem::option:
            translate_break("silently dropped: unrecognized IPv6 option encountered");

          default:
            detail::throw_exception(translate_error("unknown ICMPv6 code"));
        }
        break;

      // others; silently drop
      default:
        detail::throw_exception(translate_error("unknown ICMPv6 type"));
    }

    checksum_field(iov[1].icmp) = ~detail::i_ccs<1>(iov);

    return count;
}

template <typename Tag, int N>
std::size_t
generic(iov_ip (&iov)[N], buffer_ref b)
{
    auto bip6  = b.next_to<ipv6::header>();

    iov[1].base = bip6.data();
    iov[1].len  = bip6.size();
    checksum_field<Tag>(iov[1].base) = 0;

    const auto ph = designated((ipv4::pseudo_header)) by
    (
      ((.pip_src   = iov[0].ip.ip_src))
      ((.pip_dst   = iov[0].ip.ip_dst))
      ((.pip_proto = iov[0].ip.ip_p))
      ((.pip_len   = host_to_net<std::uint16_t>(iov[1].len)))
    );

    iovec piov[2];
    piov[0].iov_base = const_cast<void *>(static_cast<const void *>(&ph));
    piov[0].iov_len  = sizeof(ph);
    piov[1].iov_base = iov[1].iov_base;
    piov[1].iov_len  = iov[1].iov_len;

    checksum_field<Tag>(iov[1].base) = ~detail::i_ccs(piov);

    return 2;
}

template <int N, typename Inner>
std::size_t
core(iov_ip (&iov)[N], buffer_ref b, const in_addr &src, const in_addr &dst, Inner)
{
    auto &ip6 = *b.data_as<ipv6::header>();

    iov[0].ip = designated((ipv4::header)) by
    (
      ((.ip_v   = 4))
      ((.ip_hl  = sizeof(ipv4::header) / 4)) // have no option
      //((.ip_tos = <<unspecified>>))
      //((.ip_len = <<TBD>>)) // kernel fill this field iff 0
      //((.ip_id  = <<unspecified>>)) // kernel fill this field iff 0
      ((.ip_off = 0)) // fragment is not supported currently
      ((.ip_ttl = ip6.ip6_hlim))
      ((.ip_p   = ip6.ip6_nxt))
      //((.ip_sum = <<unspecified>>)) // kernel always calc checksum
      ((.ip_src = src))
      ((.ip_dst = dst))
    );
    iov[0].len = length(iov[0].ip);

    std::size_t ret = 0;
    switch (payload_protocol(ip6))
    {
      case iana::protocol_number::icmp6:
        // Adjust next-header field for ICMP
        iov[0].ip.ip_p = static_cast<std::uint8_t>(iana::protocol_number::icmp);
        ret = icmp6(iov, b, Inner{});
        temporary_show_detail("icmp6", "icmp", ip6, src, dst);
        break;

      case iana::protocol_number::tcp:
        ret = generic<tag::tcp>(iov, b);
        temporary_show_detail("tcp over ipv6", "tcp over ip", ip6, src, dst);
        break;

      case iana::protocol_number::udp:
        ret = generic<tag::udp>(iov, b);
        temporary_show_detail("udp over ipv6", "udp over ip", ip6, src, dst);
        break;

      default:
        translate_break("drop unsupported packet", false);
    }

    return ret;
}

} // namespace shinano::<anonymous-namespace>

// v6 to v4
template <>
bool
translate<ipv4>(std::tuple<raw, raw> &fwd, buffer_ref b) try
{
    auto &ip6 = *b.data_as<ipv6::header>();

    BOOST_ASSERT((ip6.ip6_vfc >> 4) == 6);

    if (ip6.ip6_hlim-- <= 1)
    {
        error::sendback_time_exceeded(std::get<1>(fwd), b);
        return true;
    }

    auto srcv4 = lookup(source(ip6));
    auto dstv4 = extract_embedded_address(dest(ip6), temporary_prefix(), temporary_plen());

    // We should treat 5 separated fields in icmp error message.
    //
    //             | icmp error message ...
    // ip  | icmp  | ip  | icmp  | payload ...
    //                v
    //             | icmp6 error message ...
    // ip6 | icmp6 | ip6 | icmp6 | payload ...
    constexpr int count = 5;

    iov_ip iov[count] = {};
    const auto iovc = core(iov, b, srcv4, dstv4, false_{});

    detail::sendmsg(std::get<0>(fwd), iov, iovc, designated((sockaddr_in)) by
    (
      ((.sin_family = ipv4::domain))
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
