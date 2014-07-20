//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef sln64_detail_exception_hpp_
#define sln64_detail_exception_hpp_

#include <string>
#include <boost/exception/exception.hpp>

#include <vector>

namespace shinano { namespace detail {

constexpr int max_backtrace_count = 20;
typedef boost::error_info<struct throw_backtrace_, std::vector<void *>> throw_backtrace;

std::string
to_string(const throw_backtrace &);

} // namespace shinano::detail

void
throw_with_errno();

} // namespace shinano

#endif
