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
#include <boost/mpl/bool.hpp>

#include "translate.hpp"
#include "translate/bib.hpp"
#include "translate/checksum.hpp"
#include <boost/range/numeric.hpp>
#include <boost/range/adaptor/dropped.hpp>

#include <boost/chrono/system_clocks.hpp>
#include <boost/chrono/io/time_point_io.hpp>

namespace shinano {

namespace {

struct iov_ip6
{
    union
    {
        int _;
        ipv6::header       ip6;
        ipv6::icmp6_header icmp6;
        tag::tcp::header   tcp;
        tag::udp::header   udp;
    };
    void *      base = &ip6;
    std::size_t len  = 0;

    void *      (&iov_base) = base;
    std::size_t (&iov_len)  = len;
};

using boost::mpl::true_;
using boost::mpl::false_;

template <int N, typename Inner>
std::size_t
core(iov_ip6 (&iov)[N], buffer_ref b, const in6_addr &src, const in6_addr &dst, Inner);


template <int N>
inline std::size_t
dispatch_core(iov_ip6 (&iov)[N], buffer_ref b, const in6_addr &src, const in6_addr &dst, false_)
{
    return core(iov, b, src, dst, true_{});
}

template <int N>
inline std::size_t
dispatch_core(iov_ip6 (&iov [[gnu::unused]])[N], buffer_ref b [[gnu::unused]],
              const in6_addr &src [[gnu::unused]], const in6_addr &dst [[gnu::unused]], true_)
{
    detail::throw_exception(translate_error("ICMP error message containts ICMP error message"));
}

void
temporary_show_detail(const char *from, const char *to,
                      const ipv4::header &iphdr, const in6_addr &src, const in6_addr &dst)
{
    const auto payload_length = net_to_host(iphdr.ip_len) - length(iphdr);

    const auto now = boost::chrono::system_clock::now();
    std::cout
      << now << ": [" << from << "] " << std::endl
      << "  " << to_string(source(iphdr)) << " -> " << to_string(dest(iphdr))
        << std::endl
      << "    TTL " << int(iphdr.ip_ttl) << " / " << payload_length << " bytes"
        << std::endl
      << "    translate to [" << to << "] "
        << to_string(src) << " -> " << to_string(dst)
        << std::endl;
}

template <typename Tag, int N>
void
finalize_ip6(iov_ip6 (&iov)[N]) noexcept
{
    using boost::adaptors::dropped;
    const std::uint16_t plen = boost::accumulate(iov | dropped(1), 0,
        [](std::uint16_t x, const iov_ip6 &v)
        {
            return x + v.len;
        });
    iov[0].ip6.ip6_plen = host_to_net(plen);

    const auto ph = designated((ipv6::pseudo_header)) by
    (
      ((.pip6_src  = iov[0].ip6.ip6_src))
      ((.pip6_dst  = iov[0].ip6.ip6_dst))
      ((.pip6_plen = iov[0].ip6.ip6_plen))
      ((.pip6_nxt  = iov[0].ip6.ip6_nxt))
    );

    iovec piov[N];
    piov[0].iov_base = const_cast<void *>(static_cast<const void *>(&ph));
    piov[0].iov_len  = sizeof(ph);
    for (int i = 1; i < N; ++i)
    {
        piov[i].iov_base = iov[i].iov_base;
        piov[i].iov_len  = iov[i].iov_len;
    }

    checksum_field<Tag>(iov[1].base) = ~detail::i_ccs(piov);
}

template <int N, typename Inner>
inline std::size_t
reassemble_icmp_error_body(iov_ip6 (&iov)[N], buffer_ref b, Inner)
{
    auto be = b.next_to<ipv4::icmp_header>();
    auto &ip = *be.data_as<ipv4::header>();
    auto srcv6 = lookup(source(ip));
    auto dstv6 = make_embedded_address(dest(ip), temporary::prefix(), temporary::plen());
    return dispatch_core(iov, be, srcv6, dstv6, Inner{});
}

template <int N, typename Inner>
std::size_t
icmp(iov_ip6 (&iov)[N], buffer_ref b, Inner)
{
    auto &ip   = *b.data_as<ipv4::header>();
    auto bip   = b.next_to<ipv4::header>();
    auto &icmp = *bip.data_as<ipv4::icmp_header>();

    iov[1].icmp6.icmp6_data32[0] = icmp.un.gateway;
    iov[1].len = length(iov[1].icmp6);

    // for ip, icmp and icmp payload
    std::size_t count = 3;

    // http://tools.ietf.org/html/rfc6145#section-4.2
    // http://tools.ietf.org/html/rfc6145#section-4.3
    switch (static_cast<iana::icmp::type>(icmp.type))
    {
      case iana::icmp::type::echo_request:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::echo_request);
        iov[2].base             = bip.next_to<ipv4::icmp_header>().data();
        iov[2].len              = plength(ip) - iov[1].len;
        break;

      case iana::icmp::type::echo_reply:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::echo_reply);
        iov[2].base             = bip.next_to<ipv4::icmp_header>().data();
        iov[2].len              = plength(ip) - iov[1].len;
        break;

      case iana::icmp::type::destination_unreachable:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::destination_unreachable);

        switch (static_cast<iana::icmp::destination_unreachable>(icmp.code))
        {
          case iana::icmp::destination_unreachable::net:
          case iana::icmp::destination_unreachable::host:
          case iana::icmp::destination_unreachable::source_route_failed:
          case iana::icmp::destination_unreachable::network_unknown:
          case iana::icmp::destination_unreachable::host_unknown:
          case iana::icmp::destination_unreachable::source_host_isolated:
          case iana::icmp::destination_unreachable::network_unreachable_for_tos:
          case iana::icmp::destination_unreachable::host_unreachable_for_tos:
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::destination_unreachable::no_route_to_destination);
            count = count - 1 + reassemble_icmp_error_body(drop<2>(iov), bip, Inner{});
            break;

          case iana::icmp::destination_unreachable::protocol:
            iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::parameter_problem);
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::parameter_problem::header_field);
            count = count - 1 + reassemble_icmp_error_body(drop<2>(iov), bip, Inner{});
            break;

          case iana::icmp::destination_unreachable::port:
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::destination_unreachable::port);
            count = count - 1 + reassemble_icmp_error_body(drop<2>(iov), bip, Inner{});
            break;

          case iana::icmp::destination_unreachable::dont_fragment:
            iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::packet_too_big);
            iov[1].icmp6.icmp6_code = 0;
            count = count - 1 + reassemble_icmp_error_body(drop<2>(iov), bip, Inner{});
            break;

          case iana::icmp::destination_unreachable::network_is_a14y_prohibited:
          case iana::icmp::destination_unreachable::host_is_a14y_prohibited:
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::destination_unreachable::administratively_prohibited);
            count = count - 1 + reassemble_icmp_error_body(drop<2>(iov), bip, Inner{});
            break;

          // NOTE: Quote from RFC6145
          //  Code 13 (Communication Administratively Prohibited):  Set
          //     the Code to 1 (Communication with destination
          //     administratively prohibited).
          //
          //  Code 14 (Host Precedence Violation):  Silently drop.
          //
          //  Code 15 (Precedence cutoff in effect):  Set the Code to 1
          //     (Communication with destination administratively
          //     prohibited).

          default:
            detail::throw_exception(translate_error("unknown ICMP code"));
        };
        break;

      case iana::icmp::type::time_exceeded:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::time_exceeded);
        iov[1].icmp6.icmp6_code = icmp.code;
        count = count - 1 + reassemble_icmp_error_body(drop<2>(iov), bip, Inner{});
        break;

      case iana::icmp::type::parameter_problem:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6::type::parameter_problem);

        switch (static_cast<iana::icmp::parameter_problem>(icmp.code))
        {
          case iana::icmp::parameter_problem::pointer_indicates:
          case iana::icmp::parameter_problem::bad_length:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::parameter_problem::header_field);
          // NOTE: Quote from RFC6145
          // Code 0 (Pointer indicates the error):  Set the Code to 0
          //    (Erroneous header field encountered) and update the
          //    pointer as defined in Figure 3.  (If the Original IPv4
          //    Pointer Value is not listed or the Translated IPv6
          //    Pointer Value is listed as "n/a", silently drop the
          //    packet.)
          // Code 2 (Bad length):  Set the Code to 0 (Erroneous header
          //    field encountered) and update the pointer as defined in
          //    Figure 3.  (If the Original IPv4 Pointer Value is not
          //    listed or the Translated IPv6 Pointer Value is listed as
          //    "n/a", silently drop the packet.)
          //
          //    +--------------------------------+--------------------------------+
          //    |   Original IPv4 Pointer Value  | Translated IPv6 Pointer Value  |
          //    +--------------------------------+--------------------------------+
          //    |  0  | Version/IHL              |  0  | Version/Traffic Class    |
          //    |  1  | Type Of Service          |  1  | Traffic Class/Flow Label |
          //    | 2,3 | Total Length             |  4  | Payload Length           |
          //    | 4,5 | Identification           | n/a |                          |
          //    |  6  | Flags/Fragment Offset    | n/a |                          |
          //    |  7  | Fragment Offset          | n/a |                          |
          //    |  8  | Time to Live             |  7  | Hop Limit                |
          //    |  9  | Protocol                 |  6  | Next Header              |
          //    |10,11| Header Checksum          | n/a |                          |
          //    |12-15| Source Address           |  8  | Source Address           |
          //    |16-19| Destination Address      | 24  | Destination Address      |
          //    +--------------------------------+--------------------------------+
          //
          //            Figure 3: Pointer Value for Translating from IPv4 to IPv6

          case iana::icmp::parameter_problem::missing_required_option:
            translate_break("silently dropped: parameter problem (missing a required option)");

          default:
            detail::throw_exception(translate_error("unknown ICMP code"));
        }
        break;

      case iana::icmp::type::timestamp_request:
      case iana::icmp::type::timestamp_reply:
        translate_break("silently dropped: timestamp message is obsoleted in icmp6");

      case iana::icmp::type::information_request:
      case iana::icmp::type::information_reply:
        translate_break("silently dropped: information message is obsoleted in icmp6");

      case iana::icmp::type::redirect:
        translate_break("silently dropped: redirect is single hop message");
      case iana::icmp::type::source_quench:
        translate_break("silently dropped: source quench is obsoleted in icmp6");

      case iana::icmp::type::router_advertisement:
      case iana::icmp::type::router_solicitation:
        translate_break("silently dropped: RA and RS are single hop message");

      case iana::icmp::type::address_mask_request:
      case iana::icmp::type::address_mask_reply:
        translate_break("silently dropped: address mask message is obsoleted in icmp6");

      case iana::icmp::type::traceroute:
        translate_break("silently dropped: traceroute message is unspecified in RFC6145");
      case iana::icmp::type::datagram_conversion_error:
        translate_break("silently dropped: datagram conversion error is unspecified in RFC6145");

      case iana::icmp::type::domain_name_request:
      case iana::icmp::type::domain_name_reply:
        translate_break("silently dropped: domain name message is unspecified in RFC6145");

      case iana::icmp::type::alternate_host_address:
        translate_break("silently dropped: alternate host address");

      // others; silently drop
      default:
        detail::throw_exception(translate_error("unknown ICMP type"));
    }

    finalize_ip6<tag::icmp6>(iov);

    return count;
}

template <typename Tag, int N>
std::size_t
generic(iov_ip6 (&iov)[N], buffer_ref b)
{
    auto bip = b.next_to<ipv4::header>();

    iov[1].base = bip.data();
    iov[1].len  = bip.size();
    checksum_field<Tag>(iov[1].base) = 0;

    finalize_ip6<Tag>(iov);

    return 2;
}

template <int N, typename Inner>
std::size_t
core(iov_ip6 (&iov)[N], buffer_ref b, const in6_addr &src, const in6_addr &dst, Inner)
{
    auto &ip = *b.data_as<ipv4::header>();

    iov[0].ip6 = designated((ipv6::header)) by
    (
      ((.ip6_vfc  = (6 << 4)))
      //((.ip6_flow = <<unspecified>>))
      //((.ip6_plen = <<TBD>>)) // kernel doesn't calc this field unlike ipv4.
      ((.ip6_nxt  = ip.ip_p))
      ((.ip6_hlim = ip.ip_ttl))
      ((.ip6_src  = src))
      ((.ip6_dst  = dst))
    );
    iov[0].len = length(iov[0].ip6);

    std::size_t ret = 0;
    switch (payload_protocol(ip))
    {
      case iana::protocol_number::icmp:
        // Adjust next-header field for ICMPv6
        iov[0].ip6.ip6_nxt = static_cast<std::uint8_t>(iana::protocol_number::icmp6);
        ret = icmp(iov, b, Inner{});
        temporary_show_detail("icmp", "icmp6", ip, src, dst);
        break;

      case iana::protocol_number::tcp:
        ret = generic<tag::tcp>(iov, b);
        temporary_show_detail("tcp over ip", "tcp over ipv6", ip, src, dst);
        break;

      case iana::protocol_number::udp:
        ret = generic<tag::udp>(iov, b);
        temporary_show_detail("udp over ip", "udp over ipv6", ip, src, dst);
        break;

      default:
        translate_break("drop unsupported packet", false);
    }

    return ret;
}

} // shinano::<anonymous-namespace>

// v4 to v6
template <>
bool
translate<ipv6>(std::reference_wrapper<raw> fwd, buffer_ref b) try
{
    auto &ip = *b.data_as<ipv4::header>();

    BOOST_ASSERT(ip.ip_v == 4);

    if (ip.ip_ttl-- <= 1)
    {
        // FIXME: Should return icmp time exceeded error message.
        translate_break("time exceeded");
    }

    // We should treat 5 separated fields in icmp error message.
    //
    //             | icmp6 error message ...
    // ip6 | icmp6 | ip6 | icmp6 | payload ...
    //                v
    //             | icmp error message ...
    // ip  | icmp  | ip  | icmp  | payload ...
    constexpr int count = 5;

    iov_ip6 iov_ip6[count] = {};

    auto srcv6 = make_embedded_address(source(ip), temporary::prefix(), temporary::plen());
    auto dstv6 = lookup(dest(ip));

    const auto iov_cnt = core(iov_ip6, b, srcv6, dstv6, false_{});

    iovec iov[count] = {};
    for (std::size_t i = 0; i < count; ++i)
    {
        iov[i].iov_base = iov_ip6[i].iov_base;
        iov[i].iov_len  = iov_ip6[i].iov_len;
    }

    fwd.get().sendmsg(iov, iov_cnt, designated((sockaddr_in6)) by
    (
      ((.sin6_family = AF_INET6))
      ((.sin6_addr   = dstv6))
    ));

    return true;
}
catch (translate_aborted &e)
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
