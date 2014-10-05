//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef sln64_detail_exception_hpp_
#define sln64_detail_exception_hpp_

#include <string>
#include <vector>

#include <boost/throw_exception.hpp>
#include <boost/exception/exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/exception/enable_error_info.hpp>

#include "config.hpp"

namespace shinano { namespace detail {

typedef boost::error_info<struct throw_backtrace_, std::vector<void *>> throw_backtrace;

std::string
to_string(const throw_backtrace &);

// Thin function should not throw any exception to avoid double throw.
bool
backtrace(throw_backtrace::value_type &) noexcept;

template <typename E>
[[noreturn]] inline void
throw_exception(E &&ex)
{
    auto ei = boost::enable_error_info(ex);

    throw_backtrace::value_type bt(config::max_backtrace_count);
    if (detail::backtrace(bt))
    {
        ei << detail::throw_backtrace(std::move(bt));
    }

    BOOST_THROW_EXCEPTION(ei);
}

} // namespace shinano::detail

[[noreturn]] void
throw_with_errno();

} // namespace shinano

#endif
