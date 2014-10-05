//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <cstddef>
#include "config.hpp"

namespace shinano { namespace detail {

struct iov_ip
{
    union
    {
        int _;
        ipv4::header      ip;
        ipv4::icmp_header icmp;
        tag::tcp::header  tcp;
        tag::udp::header  udp;
    };
    void *      base = &_;
    std::size_t len  = 0;

    void *      (&iov_base) = base;
    std::size_t (&iov_len)  = len;
};

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
    void *      base = &_;
    std::size_t len  = 0;

    void *      (&iov_base) = base;
    std::size_t (&iov_len)  = len;
};

template <typename S, typename IOV, typename Addr, std::size_t count>
inline void
sendmsg(S &sock, const IOV (&orig)[count], std::size_t n, Addr addr)
{
    BOOST_ASSERT(n <= count);

    iovec iov[count] = {};
    for (std::size_t i = 0; i < count; ++i)
    {
        iov[i].iov_base = orig[i].iov_base;
        iov[i].iov_len  = orig[i].iov_len;
    }

    sock.sendmsg(iov, n, addr);
}

template <typename S, typename IOV, typename Addr, std::size_t count>
inline void
sendmsg(S &sock, const IOV (&orig)[count], Addr addr)
{
    sendmsg(sock, orig, count, addr);
}

} } // namespace shinano::detail

