//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_translate_checksum_hpp_
#define shinano_translate_checksum_hpp_

#include <cstdint>
#include <algorithm>

#include <sys/uio.h>

#include "config.hpp"
#include "util.hpp"
#include "mpl/index_tuple.hpp"

// complement of checksum
// see: RFC700  http://tools.ietf.org/html/rfc700
//      RFC1071 http://tools.ietf.org/html/rfc1071

namespace shinano { namespace detail {

namespace aux {

inline constexpr std::uint16_t
_reducer_aux(std::uint32_t x) noexcept
{
    return x + (x >> 16);
}
inline constexpr std::uint16_t
reducer(std::uint16_t a, std::uint16_t v) noexcept
{
    return _reducer_aux(a + v);
}
template <typename V>
inline std::uint16_t
_ccs_kernel(int &x, const V &v) noexcept
{
    auto b = reinterpret_cast<const std::uint16_t *>(v.iov_base);
    auto e = b + (v.iov_len / 2);
    auto sum = std::accumulate(b, e, 0, reducer);

    if (v.iov_len % 2)
    {
        ++x;
        auto be = reinterpret_cast<const std::uint8_t *>(e);
        return reducer(sum, host_to_net<std::uint16_t>(*be << 8));
    }
    return sum;
}

template <typename V>
inline std::uint16_t
_ccs(int &x, const V &v) noexcept
{
    const bool c = x % 2;
    const auto i = _ccs_kernel(x, v);
    return c ? ~i : i;
}

template <typename V1, typename V2, typename... T>
inline std::uint16_t
_ccs(int &x, const V1 &v1, const V2 &v2, const T &... tail) noexcept
{
    // NOTE: Below line should not be merged into single return statement. Due
    //       to evaluation order of function arguments is unspecified behaviour
    //       and there is no warranty of /Sequenced Before/ for modifiable
    //       variable `x`.
    const auto a = _ccs(x, v1);
    return reducer(a, _ccs(x, v2, tail...));
}

} // namespace shinano::detail::aux

template <typename... V>
inline std::uint16_t
ccs(const V &... v) noexcept
{
    int x = 0;
    return aux::_ccs(x, v...);
}


namespace aux {

template <typename V, int N, int... I>
inline std::size_t
_i_ccs(const V (&v)[N], mpl::index_tuple<I...>) noexcept
{
    return ccs(v[I]...);
}

} // namespace shinano::detail::aux

template <typename V, int N>
inline std::size_t
i_ccs(const V (&v)[N]) noexcept
{
    return aux::_i_ccs(v, mpl::make_index_tuple<N>());
}

template <int M, typename V, int N>
inline std::size_t
i_ccs(const V (&v)[N]) noexcept
{
    return aux::_i_ccs(v, mpl::make_index_tuple<N, M>());
}

} } // namespace shinano::detail

#endif // shinano_translate_checksum_hpp_
