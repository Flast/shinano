//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_translate_checksum_hpp_
#define shinano_translate_checksum_hpp_

#include <cstdint>
#include <algorithm>

#include <sys/uio.h>

#include "util.hpp"

namespace shinano { namespace detail {

namespace aux {

inline constexpr std::uint16_t
_reducer_aux(std::uint32_t x) noexcept
{
    return x + (x >> 16);
}
inline constexpr std::uint16_t
reducer_h(std::uint16_t a, std::uint16_t v) noexcept
{
    return _reducer_aux(a + v);
}
inline constexpr std::uint16_t
reducer(std::uint16_t a, std::uint16_t v) noexcept
{
    return reducer_h(a, net_to_host(v));
}

inline std::uint16_t
_ccs_kernel(int &x, const iovec &v) noexcept
{
    auto b = reinterpret_cast<const std::uint16_t *>(v.iov_base);
    auto e = b + (v.iov_len / 2);
    auto sum = std::accumulate(b, e, 0, reducer);

    if (v.iov_len % 2)
    {
        ++x;
        return reducer(sum, (*reinterpret_cast<const std::uint8_t *>(e) << 8));
    }
    return sum;
}

inline std::uint16_t
_ccs(int &x, const iovec &v) noexcept
{
    const bool c = x % 2;
    const auto i = _ccs_kernel(x, v);
    return c ? ~i : i;
}

template <typename... T>
inline std::uint16_t
_ccs(int &x, const iovec &v1, const iovec &v2, const T &... tail) noexcept
{
    const auto a = _ccs(x, v1);
    return reducer_h(a, _ccs(x, v2, tail...));
}

} // namespace shinano::detail::aux

// return complement of checksum
// see: RFC700  http://tools.ietf.org/html/rfc700
//      RFC1071 http://tools.ietf.org/html/rfc1071
template <typename... T>
inline std::uint16_t
ccs(const T &... v) noexcept
{
    int x = 0;
    return host_to_net(aux::_ccs(x, v...));
}

} } // namespace shinano::detail

#endif // shinano_translate_checksum_hpp_
