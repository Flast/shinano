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
#include "translate/address_table.hpp"
#include "translate/checksum.hpp"
#include <boost/range/numeric.hpp>
#include <boost/range/adaptor/dropped.hpp>

namespace shinano {

namespace {

struct iov_ip6
{
    union
    {
        int _;
        ipv6::header       ip6;
        ipv6::icmp6_header icmp6;
    };
    void *      base = &ip6;
    std::size_t len  = 0;

    void *      (&iov_base) = base;
    std::size_t (&iov_len)  = len;
};

using boost::mpl::bool_;

template <int N, bool allow_recuse>
std::size_t
core(iov_ip6 (&iov)[N], buffer_ref b, const in6_addr &src, const in6_addr &dst, bool_<allow_recuse> ar);


template <int N>
inline std::size_t
dispatch_core(iov_ip6 (&iov)[N], buffer_ref b, const in6_addr &src, const in6_addr &dst, bool_<true>)
{
    return core(iov, b, src, dst, bool_<false>{});
}

template <int N>
inline std::size_t
dispatch_core(iov_ip6 (&iov)[N], buffer_ref b, const in6_addr &src, const in6_addr &dst, bool_<false>)
{
    detail::throw_exception(translate_error("ICMP error message containts ICMP error message"));
}

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

template <int N>
void
finalize_icmp6(iov_ip6 (&iov)[N]) noexcept
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

    iov[1].icmp6.icmp6_cksum = ~detail::i_ccs(piov);
}

template <int N, bool allow_recuse>
std::size_t
icmp(iov_ip6 (&iov)[N], buffer_ref b, bool_<allow_recuse> ar)
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
    switch (static_cast<iana::icmp_type>(icmp.type))
    {
      case iana::icmp_type::echo_request:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::echo_request);
        iov[2].base             = bip.next_to<ipv4::icmp_header>().data();
        iov[2].len              = plength(ip) - iov[1].len;
        break;

      case iana::icmp_type::echo_reply:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::echo_reply);
        iov[2].base             = bip.next_to<ipv4::icmp_header>().data();
        iov[2].len              = plength(ip) - iov[1].len;
        break;

      case iana::icmp_type::timestamp_request:
      case iana::icmp_type::timestamp_reply:
      case iana::icmp_type::information_request:
      case iana::icmp_type::information_reply:
        translate_break("silently dropped: obsoleted in icmp6");

      case iana::icmp_type::destination_unreachable:
        using iana::icmp6::destination_unreachable;
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::destination_unreachable);

        switch (static_cast<iana::icmp::destination_unreachable>(icmp.code))
        {
          case iana::icmp::destination_unreachable::net:
          case iana::icmp::destination_unreachable::host:
          case iana::icmp::destination_unreachable::source_route_failed:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(destination_unreachable::no_route_to_destination);

          case iana::icmp::destination_unreachable::protocol:
            detail::throw_exception(translate_error("unsupported ICMP type/code"));
            iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::parameter_problem);
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::parameter_problem::header_field);

          case iana::icmp::destination_unreachable::port:
            detail::throw_exception(translate_error("unsupported ICMP type/code"));
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(destination_unreachable::port);

          case iana::icmp::destination_unreachable::dont_fragment:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::packet_too_big);
            iov[1].icmp6.icmp6_code = 0;

          default:
            detail::throw_exception(translate_error("unknown ICMP code"));
        };
        break;

      case iana::icmp_type::redirect:
        translate_break("silently dropped");
      case iana::icmp_type::source_quench:
        translate_break("silently dropped: obsoleted in icmp6");

      case iana::icmp_type::time_exceeded:
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::time_exceeded);
        iov[1].icmp6.icmp6_code = icmp.code;
        {
            auto b = bip.next_to<ipv4::icmp_header>();
            auto &ip = *b.data_as<ipv4::header>();
            auto srcv6 = lookup(source(ip));
            auto dstv6 = make_embedded_address(dest(ip), temporary_prefix(), temporary_plen());
            count = count - 1 + dispatch_core(drop<2>(iov), b, srcv6, dstv6, ar);
        }
        break;

      case iana::icmp_type::parameter_problem:
        detail::throw_exception(translate_error("not implemented yet"));
        iov[1].icmp6.icmp6_type = static_cast<std::uint8_t>(iana::icmp6_type::parameter_problem);

        switch (static_cast<iana::icmp::parameter_problem>(icmp.code))
        {
          case iana::icmp::parameter_problem::pointer_indicates:
            detail::throw_exception(translate_error("not implemented yet"));
            iov[1].icmp6.icmp6_code = static_cast<std::uint8_t>(iana::icmp6::parameter_problem::header_field);

          default:
            detail::throw_exception(translate_error("unknown ICMP code"));
        }
        break;

      // others; silently drop
      default:
        detail::throw_exception(translate_error("unknown ICMP type"));
    }

    finalize_icmp6(iov);

    return count;
}

template <int N, bool allow_recuse>
std::size_t
core(iov_ip6 (&iov)[N], buffer_ref b, const in6_addr &src, const in6_addr &dst, bool_<allow_recuse> ar)
{
    auto &ip = *b.data_as<ipv4::header>();

    iov[0].ip6 = designated((ipv6::header)) by
    (
      ((.ip6_vfc  = (6 << 4)))
      //((.ip6_flow = <<unspecified>>))
      //((.ip6_plen = <<TBD>>)) // kernel doesn't calc this field unlike ipv4.
      ((.ip6_nxt  = static_cast<std::uint8_t>(iana::protocol_number::icmp6)))
      ((.ip6_hlim = ip.ip_ttl))
      ((.ip6_src  = src))
      ((.ip6_dst  = dst))
    );
    iov[0].len = length(iov[0].ip6);

    std::size_t ret = 0;
    switch (payload_protocol(ip))
    {
      case iana::protocol_number::icmp:
        ret = icmp(iov, b, ar);
        temporary_show_detail("icmp", "icmp6", ip, src, dst);
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

    auto srcv6 = make_embedded_address(source(ip), temporary_prefix(), temporary_plen());
    auto dstv6 = lookup(dest(ip));

    const auto iov_cnt = core(iov_ip6, b, srcv6, dstv6, bool_<true>{});

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
