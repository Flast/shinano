//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <chrono>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <boost/icl/interval_set.hpp>
using namespace boost::icl;

#include <iterator>
#include <deque>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/remove_if.hpp>

#include "detail/exception.hpp"
#include "detail/designated_initializer.hpp"

#include "translate.hpp"

#include <iostream>

namespace shinano {

namespace {

using clock      = std::chrono::steady_clock;
using time_point = clock::time_point;

struct nat_entry
{
    in_addr    v4add;
    in6_addr   v6add;
    time_point updated_at;
};

// Store v4 address in host order.
interval_set<decltype(in_addr::s_addr)> free_list;
std::deque<nat_entry> table;

void
reclaim()
{
    const auto now = clock::now();
    auto i = boost::remove_if(table, [&](const nat_entry &e)
    {
        return (now - e.updated_at) > config::table_expires_after;
    });

    std::cout << "reclaim " << std::distance(i, table.end()) << " table entries." << std::endl;;

    table.erase(i, table.end());
}


decltype(table)::iterator
allocate_v4address()
{
    auto i = free_list.begin();
    if (i == free_list.end())
    {
        auto ex = translate_error("translate v6 to v4 failed: failed to allocate v4 address");
        detail::throw_exception(ex);
    }

    auto v = i->lower();
    if (i->bounds() == interval_bounds::open()
     || i->bounds() == interval_bounds::left_open())
    {
        // in the case of (v, X) or (v, X]
        ++v;
    }
    // XXX: Should validate v4 here.
    table.emplace_back(designated((nat_entry)) by
    (
      ((.v4add.s_addr = host_to_net(v)))
    ));
    free_list -= v;

    return std::prev(table.end());
}

} // namespace shinano::<anonymous-namespace>

const in_addr &
lookup(const in6_addr &address)
{
    auto i = boost::find_if(table, [&](const nat_entry &e)
    {
        return IN6_ARE_ADDR_EQUAL(&address, &e.v6add);
    });

    if (i == table.end())
    {
        reclaim();
        i = allocate_v4address();
        i->v6add = address;
    }

    i->updated_at = clock::now();
    return i->v4add;
}

const in6_addr &
lookup(const in_addr &address)
{
    auto i = boost::find_if(table, [&](const nat_entry &e)
    {
        return address.s_addr == e.v4add.s_addr;
    });

    if (i == table.end())
    {
        auto ex = translate_error("translate v4 to v6 failed: no such NAT entry");
        detail::throw_exception(ex);
    }

    i->updated_at = clock::now();
    return i->v6add;
}


void
temporary_table_init()
{
    using interval = decltype(free_list)::interval_type;

    in_addr begin, end;
    if (inet_aton("100.64.0.0", &begin) < 0
     || inet_aton("100.127.255.255", &end) < 0)
    {
        throw_with_errno();
    }

    auto isa = interval::open(net_to_host(begin.s_addr), net_to_host(end.s_addr));
    free_list += isa;
}

} // namespace shinano
