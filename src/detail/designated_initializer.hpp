//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_detail_designated_initializer_hpp_
#define shinano_detail_designated_initializer_hpp_

#include <utility>
#include <boost/utility/identity_type.hpp>
#include <boost/preprocessor/seq/for_each.hpp>

// const auto value = designated((type)) by
// (
//     ((.mem1 = foo))
//     ((.mem2 = bar))
// );

#define designated(parenthesised_type) \
[&](BOOST_IDENTITY_TYPE(parenthesised_type) _internal_di_value_) \
  -> BOOST_IDENTITY_TYPE(parenthesised_type) \

#define IMPL_UNPARENTHESIS_DESIGNATED(...) __VA_ARGS__
#define IMPL_EXTRACT_DESIGNATED(r, data, elem) data IMPL_UNPARENTHESIS_DESIGNATED elem ;

#define by(initializers_) \
{ \
    BOOST_PP_SEQ_FOR_EACH(IMPL_EXTRACT_DESIGNATED, \
                          _internal_di_value_, \
                          initializers_) \
    return std::move(_internal_di_value_); \
}({})

#endif
