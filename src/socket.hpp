//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_socket_hpp_
#define shinano_socket_hpp_

#include <utility>
#include <string>
#include "detail/exception.hpp"

#include <unistd.h>
#include <sys/ioctl.h>
#include "config.hpp"

#include <boost/assert.hpp>

namespace shinano { namespace detail {

struct safe_desc
{
    constexpr
    safe_desc() noexcept : fd(0) { }
    safe_desc(int fd) : fd(fd) { if (fd < 0) { throw_with_errno(); } }
    safe_desc(safe_desc &&other) noexcept : fd(other.fd) { other.fd = 0; }

    ~safe_desc()
    {
        if (unsafe_native() > 0) { ::close(unsafe_native()); }
    }

    safe_desc &
    operator=(safe_desc &&other) noexcept
    {
        safe_desc(std::move(*this));
        this->~safe_desc();
        return *(new (this) safe_desc(std::move(other)));
    }

    safe_desc(const safe_desc &) = delete;
    safe_desc &
    operator=(const safe_desc &) = delete;

    int
    unsafe_native() const noexcept { return fd; }

    int
    native() const noexcept
    {
        BOOST_ASSERT(unsafe_native() > 0);
        return unsafe_native();
    }

    int
    release() noexcept
    {
        int x = unsafe_native();
        fd = 0;
        return x;
    }

private:
    int fd;
};

namespace mixin {

template <typename Desc>
struct writeable
{
    std::size_t
    write(const void *buf, size_t len)
    {
        auto err = ::write(static_cast<Desc *>(this)->native(), buf, len);
        if (err < 0) { throw_with_errno(); }
        return err;
    }

    template <typename B>
    auto
    write(const B &buf)
      -> decltype(this->write(buf.data(), buf.size()))
    {
        return write(buf.data(), buf.size());
    }
};

template <typename Desc>
struct readable
{
    std::size_t
    read(void *buf, size_t len)
    {
        auto err = ::read(static_cast<Desc *>(this)->native(), buf, len);
        if (err < 0) { throw_with_errno(); }
        return err;
    }

    template <typename B>
    auto
    read(B &buf)
      -> decltype(this->read(buf.data(), buf.capacity()))
    {
        auto ret = read(buf.data(), buf.capacity());
        buf.resize(ret);
        return ret;
    }
};

template <typename Socket>
struct controllable
{
    template <typename... Args>
    void
    ioctl(int request, Args... args)
    {
        int err = ::ioctl(static_cast<Socket *>(this)->native(), request, std::forward<Args>(args)...);
        if (err < 0) { throw_with_errno(); }
    }

    template <typename O>
    void
    setsockopt(int level, int optname, O&& optval, size_t optlen)
    {
        int err = ::setsockopt(static_cast<Socket *>(this)->native(), level, optname, std::forward<O>(optval), optlen);
        if (err < 0) { throw_with_errno(); }
    }

    void
    setsockopt(int level, int optname, bool optval)
    {
        const int val = optval ? 1 : 0;
        setsockopt(level, optname, &val, sizeof(val));
    }
};

} // namespace shinano::detail::mixin

} // namespace shinano::detail

struct controle_socket : detail::safe_desc
                       , detail::mixin::controllable<controle_socket>
{
    controle_socket();
};


struct tuntap : detail::safe_desc
              , detail::mixin::controllable<tuntap>
              , detail::mixin::readable<tuntap>
{
    static constexpr struct tap_tag {} tap = {};
    static constexpr struct tun_tag {} tun = {};

    tuntap(tap_tag, std::string name);
    tuntap(tun_tag, std::string name);

    void
    up(bool up = true);

private:
    tuntap(int flag, std::string name);

    int index;
};

template <typename Tag, typename... Args>
inline tuntap
make_tuntap(Args &&... args)
{
    return {Tag{}, std::forward<Args>(args)...};
}


struct raw : detail::safe_desc
           , detail::mixin::controllable<raw>
           , detail::mixin::writeable<raw>
{
    static constexpr struct ipv4_tag {} ipv4 = {};
    static constexpr struct ipv6_tag {} ipv6 = {};

    explicit
    raw(int family);

    raw(ipv4_tag);
    raw(ipv6_tag);
};

template <typename Tag, typename... Args>
inline raw
make_raw(Args &&... args)
{
    return {Tag{}, std::forward<Args>(args)...};
}

} // namespace shinano

#endif
