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
#include "util.hpp"
#include "socket.hpp"

namespace shinano {

struct buffer_ref
{
    using value_type     = std::uint8_t;
    using       pointer  =       value_type *;
    using const_pointer  = const value_type *;
    using       iterator =       pointer;
    using const_iterator = const_pointer;
    using size_type      = std::size_t;

    pointer   ptr_;
    size_type length_;

    constexpr size_type
    overhead() noexcept
    {
        // tun/tap interface (w/o no_pi option) will include packet informations
        // before actual packet.
        return 4;
    }

    template <typename T>
    T *
    data_as(size_type offset = 0) noexcept
    {
        return reinterpret_cast<T *>(
            static_cast<char *>(data()) + offset);
    }

    template <typename T>
    const T *
    data_as(size_type offset = 0) const noexcept
    {
        return reinterpret_cast<const T *>(
            static_cast<const char *>(data()) + offset);
    }

    size_type size() const noexcept { return length_; }
    void resize(size_type newlen) noexcept { length_ = newlen; }

          void * data()       noexcept { return ptr_; }
    const void * data() const noexcept { return ptr_; }

          iterator begin()       noexcept { return ptr_; }
    const_iterator begin() const noexcept { return ptr_; }

          iterator end()       noexcept { return std::next(begin(), size()); }
    const_iterator end() const noexcept { return std::next(begin(), size()); }


    std::uint16_t
    flags() const noexcept { return *data_as<std::uint16_t>(); }

    ieee::protocol_number
    internet_protocol() const noexcept { return *data_as<ieee::protocol_number>(2); }

    template <typename protocol>
    const typename protocol::header &
    internet_header() const noexcept
    { return *data_as<typename protocol::header>(overhead()); }

    template <typename protocol>
    buffer_ref
    next_to_ip(std::size_t offset = 0) noexcept
    {
        const auto &iphdr = internet_header<protocol>();
        const auto skip = overhead() + length(iphdr) + offset;
        return {data_as<value_type>(skip), skip};
    }
};

template <typename B>
inline buffer_ref
make_buffer_ref(B &b, std::size_t l) noexcept
{
    return {b.data(), l};
}

using input_buffer = std::array<std::uint8_t, IP_MAXPACKET>;


struct translate_error : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

template <typename Target>
bool
translate(std::reference_wrapper<raw>, buffer_ref);


void
temporary_table_init();
const in6_addr &
temporary_prefix() noexcept;
std::size_t
temporary_plen() noexcept;

} // namespace shinano

#endif
