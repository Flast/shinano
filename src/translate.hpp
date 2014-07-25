//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_translate_hpp_
#define shinano_translate_hpp_

#include <cstdint>
#include <functional>
#include <stdexcept>

#include <iterator>
#include <array>

#include "config.hpp"
#include "socket.hpp"

#include <boost/assert.hpp>

namespace shinano {

template <std::size_t maxcap>
struct buffer
{
    using size_type = std::size_t;

    constexpr size_type
    capacity() noexcept { return internal_buffer.size(); }

    size_type
    size() const noexcept { return length; }

    void
    resize(size_type newlen) noexcept
    {
        BOOST_ASSERT(capacity() >= newlen);
        length = newlen;
    }

    void *
    data() noexcept { return internal_buffer.data(); }
    const void *
    data() const noexcept { return internal_buffer.data(); }

private:
    size_type length;
    std::array<std::uint8_t, maxcap> internal_buffer;

    template <typename T>
    const T *
    data_as(size_type offset = 0) const noexcept
    {
        return static_cast<const T *>(static_cast<const void *>(
            static_cast<const char *>(data()) + offset));
    }

public:
    auto
    begin() noexcept
      -> decltype(this->internal_buffer.begin())
    { return internal_buffer.begin(); }

    auto
    begin() const noexcept
      -> decltype(this->internal_buffer.begin())
    { return internal_buffer.begin(); }

    auto
    end() noexcept
      -> decltype(this->internal_buffer.begin())
    {
        auto i = internal_buffer.begin();
        std::advance(i, size());
        return i;
    }

    auto
    end() const noexcept
      -> decltype(this->internal_buffer.begin())
    {
        auto i = internal_buffer.begin();
        std::advance(i, size());
        return i;
    }

    std::uint16_t
    flags() const noexcept { return *data_as<std::uint16_t>(); }

    ieee::protocol_number
    internet_protocol() const noexcept { return *data_as<ieee::protocol_number>(2); }

    template <typename protocol>
    auto
    internet_header() const noexcept
      -> decltype(*this->data_as<typename protocol::header>())
    { return *data_as<typename protocol::header>(4); }
};

using input_buffer = buffer<IP_MAXPACKET>;


struct translate_error : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

template <typename Target>
bool
translate(std::reference_wrapper<tuntap>, std::reference_wrapper<input_buffer>);


void
temporary_table_init();
const in6_addr &
temporary_prefix() noexcept;
std::size_t
temporary_plen() noexcept;

} // namespace shinano

#endif
