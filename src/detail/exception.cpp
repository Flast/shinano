//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <errno.h>
#include <execinfo.h>

#include <system_error>
#include <boost/throw_exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/exception/get_error_info.hpp>
#include <boost/exception/enable_error_info.hpp>
#include "detail/exception.hpp"

#include <vector>
#include <iterator>
#include <algorithm>

#include <sstream>
#include <memory>
#include "detail/memory.hpp"

namespace shinano { namespace detail {

std::string
to_string(const throw_backtrace &bt)
{
    const auto &raw = bt.value();
    std::unique_ptr<char *, detail::free_delete<char *>> symbol;
    symbol.reset(backtrace_symbols(raw.data(), raw.size()));

    std::ostringstream ostr;

    auto i = symbol.get();
    std::for_each(i, std::next(i, raw.size()), [&](const char *line)
    {
        ostr << line << std::endl;
    });

    return ostr.str();
}

} // namespace shinano::detail

void
throw_with_errno()
{
    auto ex = std::system_error(errno, std::system_category());
    auto ei = boost::enable_error_info(ex);

    std::vector<void *> bt(detail::max_backtrace_count);
    if (const int d = backtrace(bt.data(), detail::max_backtrace_count))
    {
        bt.resize(d);
        ei << detail::throw_backtrace(std::move(bt));
    }

    BOOST_THROW_EXCEPTION(ei);
}

} // namespace shinano
