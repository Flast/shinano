//          Copyright Kohei Takahashi 2014 - 2015
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <chrono>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
#include <boost/xpressive/xpressive_static.hpp>
#include <boost/icl/interval_set.hpp>

#include <iterator>
#include <deque>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/remove_if.hpp>

#include "detail/exception.hpp"
#include "detail/designated_initializer.hpp"

#include "translate.hpp"
#include "translate/bib.hpp"

#include <iostream>

namespace shinano {

namespace bib {

namespace {

using clock              = std::chrono::steady_clock;
using time_point         = clock::time_point;
using mapping_type       = boost::icl::interval_set<decltype(in_addr::s_addr)>;
using mapping_range_type = mapping_type::interval_type;

struct binding_information
{
    in_addr    v4add;
    in6_addr   v6add;
    time_point updated_at;
};

std::deque<binding_information> bib;

// Store v4 address in host order.
mapping_type config_list;
mapping_type free_list;

in6_addr prefix;
std::size_t prefix_len;

void
reclaim()
{
    const auto now = clock::now();
    auto i = boost::remove_if(bib, [&](const binding_information &e)
    {
        return (now - e.updated_at) > config::table_expires_after;
    });

    std::cout << "reclaim " << std::distance(i, bib.end()) << " bib entries." << std::endl;;

    bib.erase(i, bib.end());
}


decltype(bib)::iterator
allocate_v4address()
{
    using namespace boost::icl;

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
    bib.emplace_back(designated((binding_information)) by
    (
      ((.v4add.s_addr = host_to_net(v)))
    ));
    free_list -= v;

    return std::prev(bib.end());
}

} // namespace shinano::bib::<anonymous-namespace>

void
append_v4prefix(std::string sprefix)
{
    using namespace boost::xpressive;

    const sregex re = (s1 = (repeat<3>(+_d >> '.') >> +_d)) >> '/' >> (s2 = +_d);

    smatch res;
    if (!regex_match(sprefix, res, re))
    {
        shinano::detail::throw_exception(std::runtime_error("tmp")); // XXX
    }

    in_addr prefix;
    if (inet_aton(res.str(1).c_str(), &prefix) < 0)
    {
        throw_with_errno();
    }

    constexpr auto v4_length_in_bit = 32; // IPv4 address has 32bit length.
    const uint32_t mask = (0x1u << (v4_length_in_bit - std::stoi(res.str(2)))) - 1;

    auto range = mapping_range_type::open(
        net_to_host(prefix.s_addr) & ~mask,
        net_to_host(prefix.s_addr) |  mask);

    // Throw if it collides with new range which already configured.
    if (config_list.find(range) != config_list.end())
    {
        shinano::detail::throw_exception(std::runtime_error("tmp")); // XXX
    }
    config_list += range;
    free_list += range;

    std::cout << "A ipv4 mapped prefix has been configured: " << sprefix << std::endl;
}

} // namespace shinano::bib

const in_addr &
lookup(const in6_addr &address)
{
    auto i = boost::find_if(bib::bib, [&](const bib::binding_information &e)
    {
        return IN6_ARE_ADDR_EQUAL(&address, &e.v6add);
    });

    if (i == bib::bib.end())
    {
        bib::reclaim();
        i = bib::allocate_v4address();
        i->v6add = address;
    }

    i->updated_at = bib::clock::now();
    return i->v4add;
}

const in6_addr &
lookup(const in_addr &address)
{
    auto i = boost::find_if(bib::bib, [&](const bib::binding_information &e)
    {
        return address.s_addr == e.v4add.s_addr;
    });

    if (i == bib::bib.end())
    {
        auto ex = translate_error("translate v4 to v6 failed: no such NAT entry");
        detail::throw_exception(ex);
    }

    i->updated_at = bib::clock::now();
    return i->v6add;
}


// forward decls are in translate.hpp
namespace temporary {

void
table_init()
{
    bib::prefix_len = 96;
    if (inet_pton(AF_INET6, "64:ff9b::", &bib::prefix) != 1)
    {
        throw_with_errno();
    }
}

const in6_addr &
prefix() noexcept
{
    return bib::prefix;
}

std::size_t
plen() noexcept
{
    return bib::prefix_len;
}

} // namespace shinano::temporary

} // namespace shinano
