//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_detail_exception_hpp_
#define shinano_detail_exception_hpp_

#include <string>
#include <vector>

#include <boost/throw_exception.hpp>
#include <boost/exception/exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/exception/enable_error_info.hpp>

#include <boost/predef.h>
#if BOOST_VERSION_NUMBER(4,9,0) <= BOOST_COMP_GNUC
#define SHINANO_HAS_THROWER_CONTEXT 1
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/facilities/is_empty.hpp>
#include <boost/preprocessor/logical/not.hpp>
#else
#define SHINANO_HAS_THROWER_CONTEXT 0
#endif

#include "config.hpp"

namespace shinano { namespace detail {

typedef boost::error_info<struct throw_backtrace_, std::vector<void *>> throw_backtrace;

std::string
to_string(const throw_backtrace &);

// Thin function should not throw any exception to avoid double throw.
bool
backtrace(throw_backtrace::value_type &) noexcept;

#if SHINANO_HAS_THROWER_CONTEXT

struct caller_context
{
    const char *file;
    int         line;
    const char *function;
};

#define __SHINANO_PP_COMMA_UNLESS_EMPTY(...) \
    BOOST_PP_COMMA_IF(BOOST_PP_NOT(BOOST_PP_IS_EMPTY(__VA_ARGS__)))

#define __shinano_define_thrower_args_expansion(...)            \
    (__VA_ARGS__ __SHINANO_PP_COMMA_UNLESS_EMPTY(__VA_ARGS__)   \
     const ::shinano::detail::caller_context __ctx)
#define __shinano_decl_thrower_args_expansion(...)              \
    (__VA_ARGS__ __SHINANO_PP_COMMA_UNLESS_EMPTY(__VA_ARGS__)   \
     const ::shinano::detail::caller_context __ctx =            \
     {                                                          \
       __builtin_FILE(),                                        \
       __builtin_LINE(),                                        \
       __builtin_FUNCTION(),                                    \
     })

#define __shinano_throw_exception(e) \
    ::shinano::detail::throw_exception(e, __ctx)
#define __shinano_throw_informed_exception(ei)      \
    ::boost::throw_exception(                       \
      ei << ::boost::throw_function(__ctx.function) \
         << ::boost::throw_file(__ctx.file)         \
         << ::boost::throw_line(__ctx.line))

#else // SHINANO_HAS_THROWER_CONTEXT

#define SHINANO_HAS_THROWER_CONTEXT 0
#define __shinano_define_thrower_args_expansion(...) (__VA_ARGS__)
#define __shinano_decl_thrower_args_expansion(...) (__VA_ARGS__)
#define __shinano_throw_exception(e) \
    ::shinano::detail::throw_exception(e)
#define __shinano_throw_informed_exception(ei) \
    BOOST_THROW_EXCEPTION(ei)

#endif // SHINANO_HAS_THROWER_CONTEXT

#define __shinano_decl_thrower(name, args) \
  name __shinano_decl_thrower_args_expansion args
#define __shinano_define_thrower(name, args) \
  name __shinano_define_thrower_args_expansion args


template <typename E>
[[noreturn]] inline void
__shinano_decl_thrower(throw_exception, (E &&ex))
{
    auto ei = boost::enable_error_info(ex);

    try
    {
        throw_backtrace::value_type bt; // I bellieve default ctor of std::vector won't
                                        // throw anything even if since C++17.
        bt.resize(config::max_backtrace_count);
        if (detail::backtrace(bt))
        {
            ei << detail::throw_backtrace(std::move(bt));
        }
    }
    // Do nothing
    catch (std::bad_alloc &) { } // from allocator
    catch (std::length_error &) { } // from reserve

    __shinano_throw_informed_exception(ei);
}

} // namespace shinano::detail

[[noreturn]] void
__shinano_decl_thrower(throw_with_errno, ());

} // namespace shinano

#endif
