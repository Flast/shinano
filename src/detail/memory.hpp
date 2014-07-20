//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_detail_memory_hpp_
#define shinano_detail_memory_hpp_

#include <cstdlib>

namespace shinano { namespace detail {

template <typename T>
struct free_delete
{
    constexpr free_delete() noexcept = default;

    void
    operator()(T *p) const noexcept
    {
        static_assert(sizeof(T) > 0, "can't delete pointer to incomplete type");
        p->~T();
        std::free(static_cast<void *>(p));
    }
};

} } // namespace shinano::detail

#endif
