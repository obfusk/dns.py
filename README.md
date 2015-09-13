[]: {{{1

    File        : README.md
    Maintainer  : Felix C. Stegerman <flx@obfusk.net>
    Date        : 2015-09-12

    Copyright   : Copyright (C) 2015  Felix C. Stegerman
    Version     : v0.0.3

[]: }}}1

<!-- badge? -->

## Description

dns.py - python (2+3) DNS server + client

See `dns.py` for the code (with examples).

## Examples

```
$ ./dns.py --lookup example.com   # client
Server:         192.168.99.254
Address:        192.168.99.254#53

Non-authoritative answer:
Name:   example.com
Address: 93.184.216.34
```

```
$ ./dns.py --bind -p 5353         # server
listening on 127.0.0.1:5353 (cache=False, ttl=None) ...
query for example.com from ('127.0.0.1', 42) (ID=37)
response for example.com from ('202.12.27.33', 53) for ('127.0.0.1', 42) (ID=37)
response for example.com from ('192.35.51.30', 53) for ('127.0.0.1', 42) (ID=37)
response for example.com from ('199.43.132.53', 53) for ('127.0.0.1', 42) (ID=37)
responding to ('127.0.0.1', 42) for example.com (ID=37)
^C
```

## TODO

* no "cheating"!
* fix TODOs in DNS parsers etc.
* cleanup!
* better cache!
* better errors!

## License

GPLv3+ [1].

## References

[1] GNU General Public License, version 3
--- https://www.gnu.org/licenses/gpl-3.0.html

[]: ! ( vim: set tw=70 sw=2 sts=2 et fdm=marker : )
