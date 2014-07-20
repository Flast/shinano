//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_translate_hpp_
#define shinano_translate_hpp_

#include <cstdint>
#include <array>
#include <functional>

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
    T *
    data_as(size_type offset = 0) noexcept
    {
        return static_cast<T *>(static_cast<void *>(
            static_cast<char *>(data()) + offset));
    }

    template <typename T>
    const T *
    data_as(size_type offset = 0) const noexcept
    {
        return static_cast<const T *>(static_cast<const void *>(
            static_cast<const char *>(data()) + offset));
    }

public:
    std::uint16_t
    flags() const noexcept { return *data_as<std::uint16_t>(); }

    ieee::protocol_number
    internet_protocol() const noexcept { return *data_as<ieee::protocol_number>(2); }

    template <typename protocol>
    auto
    internet_header() noexcept
      -> decltype(this->data_as<typename protocol::header>())
    { return data_as<typename protocol::header>(4); }

    template <typename protocol>
    auto
    internet_header() const noexcept
      -> decltype(this->data_as<typename protocol::header>())
    { return data_as<typename protocol::header>(4); }
};

using input_buffer = buffer<IP_MAXPACKET>;

template <typename Target>
bool
translate(std::reference_wrapper<tuntap>, std::reference_wrapper<input_buffer>);

} // namespace shinano

#endif
