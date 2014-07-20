//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>
#include <iomanip>
#include <boost/exception/diagnostic_information.hpp>

#include <functional>

#include "detail/exception.hpp"

#include "config.hpp"
#include "socket.hpp"
#include "translate.hpp"
using namespace shinano;

template <typename CharT, typename... T>
inline std::basic_ostream<CharT, T...> &
hex4(std::basic_ostream<CharT, T...> &ostr)
{
    return ostr << std::hex << std::setw(4) << std::setfill(static_cast<CharT>('0'));
}

void
do_work(tuntap io)
{
    input_buffer buffer;

    while (true)
    {
        if (io.read(buffer) < 0) { throw_with_errno(); }

        switch (buffer.internet_protocol())
        {
          case ieee::protocol_number::ip:
            // v4 to v6
            translate<ipv6>(io, buffer);
            break;

          case ieee::protocol_number::ipv6:
            // v6 to v4
            translate<ipv4>(io, buffer);
            break;

          default:
            std::cout
              << "warning: unknown internet layer protocol"
              << " (in " << buffer.size() << " bytes)"
              << std::endl;
            break;
        }
    }
}

int main(int argc, char **argv) try
{
    auto io = make_tuntap<tuntap::tun_tag>(argv[1]);
    io.up();

    do_work(std::move(io));
}
catch (boost::exception &e)
{
    std::cout << boost::diagnostic_information(e) << std::endl;
}
