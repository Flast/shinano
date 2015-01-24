//          Copyright Kohei Takahashi 2014 - 2015
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <boost/assert.hpp>

#include <iostream>
#include <boost/exception/diagnostic_information.hpp>
#include "detail/exception.hpp"

#include "detail/dump.hpp"

#include <boost/chrono/io/timezone.hpp>
#include <boost/chrono/io/time_point_io.hpp>

#include "config.hpp"
#include "socket.hpp"
#include "translate.hpp"
#include "translate/bib.hpp"
using namespace shinano;

#include <boost/fusion/include/pair.hpp>
#include <boost/fusion/include/map.hpp>
#include <boost/fusion/include/at.hpp>
#include <boost/fusion/include/at_key.hpp>
#include <boost/fusion/include/value_at_key.hpp>
#include <boost/fusion/include/make_map.hpp>
namespace fu = boost::fusion;
#include <boost/program_options/cmdline.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
namespace po = boost::program_options;
#include <boost/make_shared.hpp>
#include <vector>
#include <string>
#include <tuple>
#include <type_traits>

void
do_work(tuntap is, raw os4, raw os6)
{
    input_buffer buffer;

    while (true)
    {
        auto bref = make_buffer_ref(buffer, is.read(buffer));

        switch (*bref.data_as<ieee::protocol_number>(2))
        {
          case ieee::protocol_number::ip:
            // v4 to v6
            if (translate<ipv6>(os6, bref.next_to(4))) { continue; }
            break;

          case ieee::protocol_number::ipv6:
            // v6 to v4
            if (translate<ipv4>(os4, bref.next_to(4))) { continue; }
            break;
        }
        std::cout
          << "warning: unknown internet layer protocol"
          << " (in " << bref.size() << " bytes)"
          << std::endl;
        debug::dump(std::cout, bref);
    }
}

void
initialize_logging()
{
    using boost::chrono::time_fmt;
    using boost::chrono::timezone;
    std::cout << time_fmt(timezone::local);
    std::cerr << time_fmt(timezone::local);
}

namespace { namespace opt {

template <typename... Pairs>
auto
make_map(Pairs&&... pairs)
{
    return fu::make_map<typename Pairs::first_type...>(pairs.second...);
}

template <typename T> struct extract;
template <typename T> struct extract<po::typed_value<T>> { typedef T type; };
template <typename T> using extract_t = typename extract<T>::type;

#define OPTION_BASE(tag, type, param, key, opt) \
  fu::make_pair<struct tag>(std::make_tuple(po::value<type>() opt, param, key))

#define OPTION_TRIPLET(tag, type, longp) \
  OPTION_BASE(tag, type, # longp             , # longp,    )
#define OPTION_QUADRUPLET(tag, type, longp, opt) \
  OPTION_BASE(tag, type, # longp             , # longp, opt)
#define OPTION_QUINTUPLET(tag, type, longp, shortp, opt) \
  OPTION_BASE(tag, type, # longp "," # shortp, # longp, opt)

const auto map = make_map(
  OPTION_QUINTUPLET(nat_prefix4, std::vector<std::string>, prefix4  , 4, ->required()),
  OPTION_QUINTUPLET(interface  , std::string             , interface, I, ->required())
);

template <typename Key>
auto desc_from_map(const char *desc)
{
    using d = po::option_description;

    auto &dp = fu::at_key<Key>(map);
    return boost::make_shared<d>(std::get<1>(dp), std::get<0>(dp), desc);
}

template <typename Key>
decltype(auto) from_map(const po::variables_map &vm)
{
    using v = typename fu::result_of::value_at_key<decltype(map), Key>::type;
    return vm[std::get<2>(fu::at_key<Key>(map))]
      .template as<extract_t<std::remove_pointer_t<std::tuple_element_t<0, v>>>>();
}

}} // namespace <anonymous-namespace>::opt

int main(int argc, char **argv) try
{
    initialize_logging();
    temporary::table_init();

    po::options_description nat_behaviours("NAT behaviours");
    nat_behaviours.add(opt::desc_from_map<opt::interface>("TUN Interface"));
    nat_behaviours.add(opt::desc_from_map<opt::nat_prefix4>("IPv4 prefix"));

    po::variables_map vm;

    po::store(po::command_line_parser(argc, argv)
                .options(nat_behaviours)
                .run(), vm);

    po::notify(vm);

    for (auto &p : opt::from_map<opt::nat_prefix4>(vm))
    {
        bib::append_v4prefix(p);
    }

    auto is = make_tuntap<tuntap::tun_tag>(opt::from_map<opt::interface>(vm));
    is.up();

    auto os4 = make_raw<raw::ipv4_tag>();
    auto os6 = make_raw<raw::ipv6_tag>();

    do_work(std::move(is), std::move(os4), std::move(os6));
}
catch (boost::exception &e)
{
    std::cout << boost::diagnostic_information(e) << std::endl;
}
