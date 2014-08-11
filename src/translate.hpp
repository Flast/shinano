//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_translate_hpp_
#define shinano_translate_hpp_

#include <cstdint>
#include <stdexcept>

#include <iterator>
#include <array>
#include <tuple>

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

    size_type size() const noexcept { return length_; }
    void resize(size_type newlen) noexcept { length_ = newlen; }

          iterator begin()       noexcept { return ptr_; }
    const_iterator begin() const noexcept { return ptr_; }

          iterator end()       noexcept { return std::next(begin(), size()); }
    const_iterator end() const noexcept { return std::next(begin(), size()); }

          void * data()       noexcept { return ptr_; }
    const void * data() const noexcept { return ptr_; }

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

    buffer_ref
    next_to(size_type skip) noexcept
    {
        return {data_as<value_type>(skip), size() - skip};
    }

    template <typename T>
    buffer_ref
    next_to() noexcept { return next_to(length(*data_as<T>())); }
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
translate(std::tuple<raw, raw> &, buffer_ref);

struct translate_breaked : std::exception
{
    explicit
    translate_breaked(std::string what, bool ret = true)
      : _w(what), _ret(ret) { }

    virtual const char *
    what() const noexcept override
    {
        return _w.c_str();
    }

    bool
    ret() const noexcept { return _ret; }

private:
    std::string _w;
    bool        _ret;
};

template <typename... T>
inline void
translate_break(T &&... v)
{
    throw translate_breaked(std::forward<T>(v)...);
}


void
temporary_table_init();
const in6_addr &
temporary_prefix() noexcept;
std::size_t
temporary_plen() noexcept;

} // namespace shinano

#endif
