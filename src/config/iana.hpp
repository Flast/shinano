//          Copyright Kohei Takahashi 2014
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef shinano_config_iana_hpp_
#define shinano_config_iana_hpp_

#include <cstdint>

namespace iana {

// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
enum class protocol_number : std::uint8_t
{
    hopopt     = 0,
    icmp       = 1,
    igmp       = 2,
    ipv4       = 4,
    tcp        = 6,
    udp        = 17,
    dccp       = 33,
    ipv6       = 41,
    ipv6_route = 43,
    ipv6_frag  = 44,
    gre        = 47,
    icmp6      = 58,
    ipv6_nonxt = 59,
    ipv6_opts  = 60,
};

// http://tools.ietf.org/html/rfc792
namespace icmp {

// ICMP message type
enum class type : std::uint8_t
{
    destination_unreachable = 3,
    time_exceeded = 11,
    parameter_problem = 12,
    source_quench = 4,
    redirect = 5,

    echo_request = 8,
    echo_reply = 0,

    timestamp_request = 13,
    timestamp_reply = 14,

    information_request = 15,
    information_reply = 16,
};

enum class destination_unreachable : std::uint8_t
{
    net = 0,
    host = 1,
    protocol = 2,
    port = 3,
    fragmentation_needed = 4,
    dont_fragment = fragmentation_needed,
    source_route_failed = 5,
};

enum class time_exceeded : std::uint8_t
{
    ttl_exceeded = 0,
    fragment_reassembly = 1,
};

enum class parameter_problem : std::uint8_t
{
    pointer_indicates = 0,
};

enum class redirect : std::uint8_t
{
    for_network = 0,
    for_host = 1,
    tos_and_for_network = 2,
    tos_and_for_host = 3,
};

} // namespace iana::icmp

using icmp_type [[gnu::deprecated("use iana::icmp::type")]] = icmp::type;


// http://tools.ietf.org/html/rfc4443
namespace icmp6 {

// ICMPv6 message type
enum class type : std::uint8_t
{
    // From 1 to 127 show error message.
    destination_unreachable = 1,
    packet_too_big = 2,
    time_exceeded = 3,
    parameter_problem = 4,

    experimentation_error_1 = 100,
    experimentation_error_2 = 101,

    reserved_for_error = 127,

    // From 128 to 255 show informational message.
    echo_request = 128,
    echo_reply = 129,

    experimentation_informational_1 = 200,
    experimentation_informational_2 = 201,

    reserved_for_informational = 255,
};

enum class destination_unreachable : std::uint8_t
{
    no_route_to_destination = 0,
    administratively_prohibited = 1,
    beyond_scope_of_source = 2,
    address = 3,
    port = 4,
    ingress_egress_policy = 5,
    reject = 6,
};

enum class time_exceeded : std::uint8_t
{
    hop_limit_exceeded = 0,
    fragment_reassembly = 1,
};

enum class parameter_problem : std::uint8_t
{
    header_field = 0,
    next_header = 1,
    option = 2,
};

} // namespace iana::icmp6

using icmp6_type [[gnu::deprecated("use iana::icmp6::type")]] = icmp6::type;

} // namespace iana

#endif
