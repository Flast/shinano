Stateless NAT64 user-mode implementation
========================================

Author
------

- Kohei Takahashi <flast@tsukuba.wide.ad.jp>

References
----------

- [RFC2765][2765] - Stateless IP/ICMP Translation Algorithm (SIIT)
  + obsoleted by: [RFC6145][6145]
- [RFC5382][5382] - NAT Behavioral Requirements for TCP
- [RFC6052][6052] - IPv6 Addressing of IPv4/IPv6 Translators
  + references: [RFC1918][1918], [RFC5735 - Section 3][5735-s3]
- [RFC6144][6144] - Framework for IPv4/IPv6 Translation
- [RFC6145][6145] - IP/ICMP Translation Algorithm
  + updated by: [RFC6791][6791]
  + references: [RFC4966][4966]
- [RFC6146][6146] - Stateful NAT64: Network Address and Protocol Translation from IPv6 Clients to IPv4 Servers
- [RFC6791][6791] - Stateless Source Address Mapping for ICMPv6 Packets

  [1918   ]: http://tools.ietf.org/html/rfc1918
  [2765   ]: http://tools.ietf.org/html/rfc2765
  [4966   ]: http://tools.ietf.org/html/rfc4966
  [5382   ]: http://tools.ietf.org/html/rfc5382
  [5735-s3]: http://tools.ietf.org/html/rfc5735#section-3
  [6052   ]: http://tools.ietf.org/html/rfc6052
  [6144   ]: http://tools.ietf.org/html/rfc6144
  [6145   ]: http://tools.ietf.org/html/rfc6145
  [6146   ]: http://tools.ietf.org/html/rfc6146
  [6791   ]: http://tools.ietf.org/html/rfc6791

License
-------

              Copyright Kohei Takahashi 2014
     Distributed under the Boost Software License, Version 1.0.
        (See accompanying file LICENSE_1_0.txt or copy at
              http://www.boost.org/LICENSE_1_0.txt)
