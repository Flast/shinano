//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_detail_dump_hpp_
#define shinano_detail_dump_hpp_

#include <iterator>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <boost/range/algorithm_ext/iota.hpp>

namespace shinano { namespace debug {

namespace detail {

template <typename CharT, typename... T, typename I>
inline I
dump_line(std::basic_ostream<CharT, T...> &ostr, I itr, const I end)
{
    for (int i = 0; itr != end && i < 16; ++i, ++itr)
    {
        ostr << ' ' << std::setw(2) << std::setfill('0')
          << static_cast<int>(*itr);
    }
    ostr << std::endl;
    return itr;
}

template <typename CharT, typename... T, typename R>
inline auto
dump_line(std::basic_ostream<CharT, T...> &ostr, const R &range)
  -> decltype(dump_line(ostr, std::begin(range), std::end(range)))
{
    return dump_line(ostr, std::begin(range), std::end(range));
}

} // namespace shinano::debug::detail

template <typename CharT, typename... T, typename R>
inline void
dump(std::basic_ostream<CharT, T...> &ostr, const R &range)
{
    std::cout << std::hex;
    {
        int a[16];
        boost::iota(a, 0);
        detail::dump_line(ostr << "      ", a);
    }

    int linenum = 0;
    for (auto i = std::begin(range), e = std::end(range); i != e; linenum += 16)
    {
        ostr << "0x" << std::setw(4) << std::setfill('0') << linenum;
        i = detail::dump_line(ostr, i, e);
    }
    std::cout << std::dec;
}

} } // namespace shinano::debug

#endif
