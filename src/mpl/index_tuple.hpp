//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_mpl_index_tuple_hpp_
#define shinano_mpl_index_tuple_hpp_

namespace shinano { namespace mpl {

template <int...> struct index_tuple { };

template <int, typename> struct push_back;

template <int t, int... h>
struct push_back<t, index_tuple<h...>>
{ typedef index_tuple<h..., t> type; };

template <int I, int M>
struct index_tuple_wrap
{
    typedef index_tuple_wrap<I - 1, M> prev;
    typedef typename push_back<I - 1, typename prev::type>::type type;
};

template <int M>
struct index_tuple_wrap<M, M>
{
    typedef index_tuple<> type;
};

template <int N, int M = 0>
inline constexpr typename index_tuple_wrap<N, M>::type
make_index_tuple() noexcept { return {}; }

} } // namespace shinano::mpl

#endif
