#!/usr/bin/python

# --                                                            ; {{{1
#
# File        : dns.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-06-18
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.0.1
# License     : LGPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
"""
Python (2+3) DNS server + client

Examples
--------

>>> import dns as D

... TODO ...


References
----------

https://en.wikipedia.org/wiki/Domain_Name_System
https://en.wikipedia.org/wiki/Root_name_server
"""
                                                                # }}}1

from __future__ import print_function

import argparse, binascii, itertools, os, re, select, struct, sys
import time
import socket as S

if sys.version_info.major == 2:                                 # {{{1
  def b2s(x):
    """convert bytes to str"""
    return x
  def s2b(x):
    """convert str to bytes"""
    return x
else:
  def b2s(x):
    """convert bytes to str"""
    if isinstance(x, str): return x
    return x.decode("utf8")
  def s2b(x):
    """convert str to bytes"""
    if isinstance(x, bytes): return x
    return x.encode("utf8")
  xrange = range
                                                                # }}}1

__version__       = "0.0.1"

DEFAULT_ID        = os.getpid()
DEFAULT_PORT      = 53

DEFAULT_TYPE      = "A"
DEFAULT_CLASS     = "IN"

RESOLV_CONF       = "/etc/resolv.conf"

class Error(RuntimeError): pass

# TODO
def main(*args):                                                # {{{1
  n = argument_parser().parse_args(args)
  if n.test:
    import doctest
    doctest.testmod(verbose = n.verbose)
    return 0
  try:
    pass  # TODO
  except KeyboardInterrupt:
    return 1
  return 0
                                                                # }}}1

# TODO
def argument_parser():                                          # {{{1
  p = argparse.ArgumentParser(description = "nslookup + DNS server",
                              add_help    = False)
  p.add_argument("--help", action = "help",
                 help = "show this help message and exit")
  p.add_argument("--version", action = "version",
                 version = "%(prog)s {}".format(__version__))
  p.add_argument("--test", action = "store_true",
                 help = "run tests (and no nslookup or DNS server)")
  p.add_argument("--verbose", "-v", action = "store_true",
                 help = "run tests verbosely")
  p.set_defaults()
  return p
                                                                # }}}1

# ... strip(".") ...

# ... TODO ...

def default_nameservers(resolv_conf = RESOLV_CONF):             # {{{1
  """
  get default nameservers from resolv.conf

  >>> import dns as D
  >>> D.default_nameservers("test/resolv.conf")
  ['192.168.1.254']
  """

  servers = []
  try:
    with open(resolv_conf) as f:
      for line in f.readlines():
        m = re.match("nameserver\s+([0-9.]+)", line)
        if m: servers.append(m.group(1))
  except IOError as e:
    if e.errno != 2: raise
    else: return None   # no such file
  return servers
                                                                # }}}1

# === DNS ========================================================= #
# identification (16)             | flags (16)                      #
# QDCOUNT (16)                    | ANCOUNT (16)                    #
# NSCOUNT (16)                    | ARCOUNT (16)                    #
#                           ... data ...                            #
# ================================================================= #

# QD = questions, AN = answers, NS = authority, AR = additional

# === DNS flags =================================================== #
# |      0|      1|      2|      3|      4|      5|      6|      7| #
# | QR    |           OPCODE (4)          | AA    | TC    | RD    | #
# |      8|      9|     10|     11|     12|     13|     14|     15| #
# | RA    | Z     | AD    | CD    |           RCODE (4)           | #
# ================================================================= #

# QR = 1 if reply (0 if query)
# AA = 1 if authoritative answer
# RD = 1 if recursion desired
# RA = 1 if recursion available

# === DNS Question ================================================ #
#                           ... QNAME ...                           #
# QTYPE (16)                      | QCLASS (16)                     #
# ================================================================= #

# === DNS RR ====================================================== #
#                           ... NAME ...                            #
# TYPE (16)                       | CLASS (16)                      #
#                              TTL (32)                             #
#                            RDLENGTH (16)                          #
#                           ... RDATA ...                           #
# ================================================================= #

# TODO
def unpack_dns(pkt):                                            # {{{1
  """
  unpack DNS packet

  >>> import binascii as B, dns as D
  >>> p = b"70930100000100000000000003777777066f626675736b0263680000010001"
  >>> u = unpack_dns(B.unhexlify(p))
  >>> # TODO
  """

  ID, flag_bits, n_qr, n_an, n_ns, n_ar = \
    struct.unpack("!HHHHHH", pkt[:12])
  qr, an, ns, ar = [], [], [], []
  flags = dict(
    QR = flag_bits >> 15 & 1, AA = flag_bits >> 10 & 1,
    RD = flag_bits >>  8 & 1, RA = flag_bits >>  7 & 1
  )
  qr, offset1 = unpack_dns_qr(n_qr, pkt[12:])
  an, offset2 = unpack_dns_an(n_an, pkt[12+offset1:])
  ns, offset3 = unpack_dns_ns(n_ns, pkt[12+offset1+offset2:])
  ar, offset4 = unpack_dns_ar(n_ar, pkt[12+offset1+offset2+offset3:])
  return dict(ID = ID, flags = flags, qr = qr, an = an,
                                      ns = ns, ar = ar)
                                                                # }}}1

# TODO
def unpack_dns_qr(n, data):
  """unpack DNS questions"""
  return None, 0

# TODO
def unpack_dns_an(n, data):
  return None, 0

# TODO
def unpack_dns_ns(n, data):
  return None, 0

# TODO
def unpack_dns_ar(n, data):
  return None, 0

# TODO
def unpack_dns_rr(n, data):
  return None, 0

def unpack_dns_labels(data, pkt = None):                        # {{{1
  """
  unpack DNS domain name (as a sequence of labels, as per RFC 1035)

  >>> import binascii as B, dns as D
  >>> l1 = B.unhexlify(b"03777777066f626675736b02636800")
  >>> D.unpack_dns_labels(l1)
  ('www.obfusk.ch', 15)
  >>> l2 = B.unhexlify(b"03666f6fc004")
  >>> D.unpack_dns_labels(l2, l1)
  ('foo.obfusk.ch', 6)
  """

  labels = []; ptr = False; offset = 0
  while len(data):
    n = b2i(data[0])
    if n == 0:
      if not ptr: offset += 1
      break
    if n >> 6 == 0b11:
      if ptr: raise Error("will only follow one pointer")
      data, ptr = pkt[(n & 0b111111)+b2i(data[1]):], True
      offset += 2
    else:
      label, data = data[1:n+1], data[n+1:]
      labels.append(b2s(label))
      if not ptr: offset += n+1
  return ".".join(labels), offset
                                                                # }}}!

# ... TODO ...

def dns_query(qr, ID = DEFAULT_ID, **flags):                    # {{{1
  """
  create DNS query

  >>> import binascii as B, dns as D
  >>> q = D.dns_question("www.obfusk.ch")
  >>> p = D.dns_query([q], ID = 0x7093)
  >>> D.b2s(B.hexlify(p))
  '70930100000100000000000003777777066f626675736b0263680000010001'
  """

  return dns_packet(ID, qr = qr, **dict(QR = 0, RD = 1, **flags))
                                                                # }}}1

# TODO
def dns_query_response():
  pass

def dns_packet(ID, qr = [], an = [], ns = [], ar = [], **flags):
  """create DNS packet"""
  return  dns_header(ID, n_qr = len(qr), n_an = len(an),
                         n_ns = len(ns), n_ar = len(ar), **flags) \
          + b"".join(itertools.chain(qr, an, ns, ar))

def dns_question(name, TYPE = None, CLASS = None):
  """create DNS question (as per RFC 1035)"""
  if TYPE  is None: TYPE  = TYPES[DEFAULT_TYPE]
  if CLASS is None: CLASS = CLASSES[DEFAULT_CLASS]
  return dns_labels(name) + struct.pack("!HH", TYPE, CLASS)

def dns_rr(name, TYPE = None, CLASS = None, TTL = 0, RDATA = b""):
  """create DNS Resource Record (as per RFC 1035)"""
  if TYPE  is None: TYPE  = TYPES[DEFAULT_TYPE]
  if CLASS is None: CLASS = CLASSES[DEFAULT_CLASS]
  return  dns_labels(name) + \
          struct.pack("!HHiH", TYPE, CLASS, TTL, len(RDATA)) + RDATA
  # NB: RFC 1035 says TTL is signed (& unsigned ?!)

# TODO
def dns_labels(name):                                           # {{{1
  """
  DNS domain name (as a sequence of labels, as per RFC 1035)

  >>> import binascii as B, dns as D
  >>> D.b2s(B.hexlify(D.dns_labels("www.obfusk.ch")))
  '03777777066f626675736b02636800'
  """

  # TODO: create pointers?!
  labels = name.split(".")
  return b"".join(
    struct.pack("!B", len(l)) + s2b(l) for l in labels
  ) + struct.pack("!B", 0)
                                                                # }}}!

def dns_header(ID, QR = 0, AA = 0, RD = 0, RA = 0,              # {{{1
               n_qr = 0, n_an = 0, n_ns = 0, n_ar = 0):
  """
  create DNS header

  >>> import binascii as B, dns as D
  >>> h = D.dns_header(0x87fa, QR = 1, n_qr = 1, n_ns = 13, n_ar = 16)
  >>> D.b2s(B.hexlify(h))
  '87fa800000010000000d0010'
  """

  flag_bits = QR << 15 | AA << 10 | RD << 8 | RA << 7
  return struct.pack("!HHHHHH", ID, flag_bits, n_qr, n_an, n_ns, n_ar)
                                                                # }}}1

# TODO: incomplete
TYPES = dict(                                                   # {{{1
  A     = 1,
  NS    = 2,
  CNAME = 5,
  SOA   = 6,
)                                                               # }}}1

TYPES_REV = dict( (v,k) for (k,v) in TYPES.items() )

# TODO: incomplete
CLASSES     = dict(IN = 1)
CLASSES_REV = dict( (v,k) for (k,v) in CLASSES.items() )

ROOT_SERVERS = dict(                                            # {{{1
  a = "198.41.0.4",
  b = "192.228.79.201",
  c = "192.33.4.12",
  d = "199.7.91.13",
  e = "192.203.230.10",
  f = "192.5.5.241",
  g = "192.112.36.4",
  h = "128.63.2.53",
  i = "192.36.148.17",
  j = "192.58.128.30",
  k = "193.0.14.129",
  l = "199.7.83.42",
  m = "202.12.27.33",
)                                                               # }}}1

def print_(x):
  """print w/o newline and flush"""
  print(x, end = ""); sys.stdout.flush()

def b2i(x):
  """convert bytes to integer"""
  if isinstance(x, int): return x
  return int(binascii.hexlify(x), 16)

def i2b(x, n = 1):
  """convert integer to bytes of length (at least) n"""
  if isinstance(x, bytes): return x
  return binascii.unhexlify(s2b("%0*x" % (n*2,x)))

if __name__ == "__main__":
  sys.exit(main(*sys.argv[1:]))

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
