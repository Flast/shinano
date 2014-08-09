//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_translate_address_table_hpp_
#define shinano_translate_address_table_hpp_

#include <netinet/in.h>

namespace shinano {

const in_addr &
lookup(const in6_addr &address);

const in6_addr &
lookup(const in_addr &address);

} // namespace shinano

#endif
