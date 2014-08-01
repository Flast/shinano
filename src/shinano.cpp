//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>
#include <boost/exception/diagnostic_information.hpp>
#include "detail/exception.hpp"

#include "detail/dump.hpp"

#include "config.hpp"
#include "socket.hpp"
#include "translate.hpp"
using namespace shinano;

void
do_work(tuntap is, raw os4, raw os6)
{
    input_buffer buffer;

    while (true)
    {
        auto bref = [&]() -> buffer_ref
        {
            const auto len = is.read(buffer);
            if (len < 0) { throw_with_errno(); }
            return make_buffer_ref(buffer, len);
        }();

        switch (bref.internet_protocol())
        {
          case ieee::protocol_number::ip:
            // v4 to v6
            if (translate<ipv6>(os6, bref)) { continue; }
            break;

          case ieee::protocol_number::ipv6:
            // v6 to v4
            if (translate<ipv4>(os4, bref)) { continue; }
            break;
        }
        std::cout
          << "warning: unknown internet layer protocol"
          << " (in " << bref.size() << " bytes)"
          << std::endl;
        debug::dump(std::cout, bref);
    }
}

int main(int argc, char **argv) try
{
    temporary_table_init();

    auto is = make_tuntap<tuntap::tun_tag>(argv[1]);
    is.up();

    auto os4 = make_raw<raw::ipv4_tag>();
    auto os6 = make_raw<raw::ipv6_tag>();

    do_work(std::move(is), std::move(os4), std::move(os6));
}
catch (boost::exception &e)
{
    std::cout << boost::diagnostic_information(e) << std::endl;
}
