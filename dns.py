#!/usr/bin/python

# --                                                            ; {{{1
#
# File        : dns.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-06-18
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.0.2
# License     : LGPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
"""
Python (2+3) DNS server + client

Examples
--------

>>> import dns as D

>>> D.verbose_nslookup("example.com")             # doctest: +ELLIPSIS
Server:         ...
Address:        ...#53
<BLANKLINE>
Non-authoritative answer:
Name:   example.com
Address: 93.184.216.34

>>> D.verbose_nslookup("obfusk.ch")               # doctest: +ELLIPSIS
Server:         ...
Address:        ...#53
<BLANKLINE>
Non-authoritative answer:
Name:   obfusk.ch
Address: 213.108.108.143

>>> D.verbose_nslookup("google.com", "8.8.8.8")   # doctest: +ELLIPSIS
Server:         8.8.8.8
Address:        8.8.8.8#53
<BLANKLINE>
Non-authoritative answer:
Name:   google.com
Address: ...
Name:   google.com
Address: ...
...

>>> D.verbose_nslookup("google.com", "ns1.google.com") # doctest: +ELLIPSIS
Server:         ns1.google.com
Address:        ...#53
<BLANKLINE>
Name:   google.com
Address: ...
Name:   google.com
Address: ...
...

>>> D.verbose_nslookup("localhost.github.com")    # doctest: +ELLIPSIS
Server:         ...
Address:        ...#53
<BLANKLINE>
Non-authoritative answer:
localhost.github.com    canonical name = github.map.fastly.net.
Name:   github.map.fastly.net
Address: 23.235.43.133

>>> D.verbose_nslookup("nonexistent.example.com") # doctest: +ELLIPSIS
Server:         ...
Address:        ...#53
<BLANKLINE>
** server can't find nonexistent.example.com: NXDOMAIN
1


>>> import subprocess, sys, time
>>> a = ('127.0.0.1', 5301)
>>> c = [sys.executable, "dns.py", "-B", a[0], "-p", str(a[1])]
>>> p = subprocess.Popen(c)
>>> time.sleep(1)

>>> D.verbose_nslookup("example.com", *a)
Server:         127.0.0.1
Address:        127.0.0.1#5301
<BLANKLINE>
Non-authoritative answer:
Name:   example.com
Address: 93.184.216.34

>>> D.verbose_nslookup("nonexistent.example.com", *a)
Server:         127.0.0.1
Address:        127.0.0.1#5301
<BLANKLINE>
** server can't find nonexistent.example.com: NXDOMAIN
1

>>> cmd   = sys.executable + " dns.py -l {} -p 5301 -s 127.0.0.1"
>>> cmds  = "{} & {} & wait".format(cmd.format("example.com"),
...                                 cmd.format("obfusk.ch"))
>>> print(D.b2s(subprocess.check_output(cmds, shell = True))) # doctest: +ELLIPSIS
Server:         127.0.0.1
...
Address: 93.184.216.34
...

>>> p.kill()


>>> import subprocess, sys, time
>>> a = ('127.0.0.1', 5302)
>>> c = [sys.executable, "dns.py", "-B", a[0], "-p", str(a[1]),
...      "-c", "-t", "2"]
>>> p = subprocess.Popen(c)
>>> time.sleep(1)

>>> D.verbose_nslookup("example.com", *a)
Server:         127.0.0.1
Address:        127.0.0.1#5302
<BLANKLINE>
Non-authoritative answer:
Name:   example.com
Address: 93.184.216.34

>>> D.verbose_nslookup("example.com", *a)
Server:         127.0.0.1
Address:        127.0.0.1#5302
<BLANKLINE>
Non-authoritative answer:
Name:   example.com
Address: 93.184.216.34

>>> time.sleep(3)

>>> D.verbose_nslookup("example.com", *a)
Server:         127.0.0.1
Address:        127.0.0.1#5302
<BLANKLINE>
Non-authoritative answer:
Name:   example.com
Address: 93.184.216.34

>>> p.kill()


References
----------

https://en.wikipedia.org/wiki/Domain_Name_System
https://en.wikipedia.org/wiki/Root_name_server
"""
                                                                # }}}1

from __future__ import print_function

import  argparse, binascii, itertools, json, os, random, re, select, \
        struct, sys, time
import  socket as S

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

__version__       = "0.0.2"

DEFAULT_BIND      = "127.0.0.1"
DEFAULT_PORT      = 53

DEFAULT_ID        = lambda: os.getpid() ^ random.randint(0, 0xffff)
DEFAULT_TIMEOUT   = 10
DEFAULT_TTL       = 3600

DEFAULT_TYPE      = "A"
DEFAULT_CLASS     = "IN"

RESOLV_CONF       = "/etc/resolv.conf"
CACHE_FILE        = "cache"

class Error(RuntimeError): pass
class UnexpectedDataError(Error): pass

class PacketWrapper(object):
  def __init__(self, p): self.p = p
  def __repr__(self): return "<PacketWrapper#" + repr(self.p) + ">"

def main(*args):                                                # {{{1
  p = argument_parser(); n = p.parse_args(args)
  if n.test:
    import doctest
    doctest.testmod(verbose = n.verbose)
    return 0
  try:
    if n.lookup:
      return verbose_nslookup(n.lookup, n.server, n.port, n.timeout)
    elif n.bind:
      if n.caching:
        cache = load_cache() or {}; cache["__TTL__"] = n.ttl
      else:
        cache = None
      try:
        return verbose_server(n.bind, n.port, cache)
      finally:
        if cache: save_cache(cache)
    else:
      print("{}: error: neither --lookup not --bind specified" \
              .format(p.prog), file = sys.stderr)
      return 2
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
  p.add_argument("--lookup", "-l", metavar = "NAME", action = "store",
                 help = "look up information for host NAME")
  p.add_argument("--bind", "-B", action = "store", nargs='?',
                 metavar = "ADDR", const = DEFAULT_BIND,
                 help = "run the DNS server and bind to ADDR "
                        "(default: %(default)s)")
  p.add_argument("--caching", "-c", action = "store_true",
                 help = "enable caching")
  p.add_argument("--port", "-p", type = int, action = "store",
                 help = "the port for nslookup to connect to, "
                        "or the server to listen on "
                        "(default: %(default)s)")
  p.add_argument("--server", "-s", action = "store",
                 help = "the lookup server "
                        "(current default: %(default)s)")
  p.add_argument("--timeout", "-w", type = float, action = "store",
                 help = "the timeout "
                        "(default: %(default)s)")
  p.add_argument("--ttl", "-t", type = int, action = "store",
                 help = "the TTL (default: %(default)s)")
  p.add_argument("--test", action = "store_true",
                 help = "run tests (and no nslookup or DNS server)")
  p.add_argument("--verbose", "-v", action = "store_true",
                 help = "run tests verbosely")
  p.set_defaults(
    caching = False,
    lookup  = None,
    port    = DEFAULT_PORT,
    server  = default_nameserver(),
    timeout = DEFAULT_TIMEOUT,
    ttl     = DEFAULT_TTL,
  )
  return p
                                                                # }}}1

# TODO
def verbose_nslookup(name, server = None, port = DEFAULT_PORT,  # {{{1
                    timeout = DEFAULT_TIMEOUT):
  """nslookup verbosely"""

  name = name.strip(".")
  if server is None:
    server = default_nameserver()
    if server is None: raise Error("no server") # TODO
  if server.split(".")[-1].isdigit():
    host = addr = server
  else:
    info = S.gethostbyname_ex(server)
    host, addr = info[0], info[2][0]
  print("{:15} {}".format("Server:", server))
  print("{:15} {}#{}".format("Address:", addr, port))
  print()
  p = nslookup((addr, port), name, timeout)
  if p == TIMEOUT:
    print("timeout!") # TODO
    return 1
  elif p["flags"]["RCODE"] != 0:
    c = RCODES.get(p["flags"]["RCODE"], "???")
    print("** server can't find {}: {}".format(name, c))
    return 1
  else:
    if not p["flags"]["AA"]:
      print("Non-authoritative answer:")
    for a in p["an"]:
      if a["CLASS"] != CLASSES["IN"]:
        raise("unexpeced CLASS!") # TODO
      if a["TYPE"] == TYPES["A"]:
        name    = a["name"]
        address = S.inet_ntoa(a["RDATA"])
        print("{:7} {}".format("Name:", name))
        print("{} {}".format("Address:", address))
      elif a["TYPE"] == TYPES["CNAME"]:
        name    = a["name"]
        cname   = unpack_dns_labels(a["RDATA"], p["pkt"])[0]
        if not cname.endswith("."): cname += "."
        print("{:23} canonical name = {}".format(name, cname))
      else:
        raise("unexpeced TYPE!") # TODO
                                                                # }}}1

def nslookup(addr, name, timeout):                              # {{{1
  """use the server at addr:port to look up name"""

  sock = S.socket(S.AF_INET, S.SOCK_DGRAM)
  try:
    ID  = send_query(sock, addr, name)
    p   = recv_response(sock, addr, ID, timeout)
    return p
  finally:
    sock.close()
                                                                # }}}1

# TODO
def verbose_server(bind, port, cache = None, stop = None):      # {{{1
  """DNS server"""

  print("listening on {}:{} (cache={}, ttl={}) ..." \
        .format(bind, port, cache is not None,
                cache and cache["__TTL__"] ))
  sock = S.socket(S.AF_INET, S.SOCK_DGRAM)
  try:
    sock.setblocking(0); sock.bind((bind, port))
    conns = {}; socks = [sock]
    while stop is None or not stop.is_set():
      r, _, _ = select.select(socks, [], [], 1)
      for s in r:
        data, addr  = s.recvfrom(1024); p = unpack_dns(data)
        ID          = p["ID"]   # TODO: unique enough?!
        try:
          if s is sock:
            conns[ID] = {}
            handle_query(p, addr, conns[ID], socks, cache)
          else:
            handle_query_reponse(p, addr, conns, socks, cache)
        except UnexpectedDataError as e:
          if conns[ID]["sock"]:
            conns[ID]["sock"].close()
            socks.remove(conns[ID]["sock"])   # TODO: always rm!
          del conns[ID]
          print("Error:", e)
  finally:
    sock.close()
                                                                # }}}1

# TODO
def handle_query(p, addr, conn, socks, cache):                  # {{{1
  """handle query"""

  conn.update(sock = None, addr = addr)
  if len(p["qr"]) != 1:
    raise UnexpectedDataError("not a single query") # TODO
  conn["query"] = q = p["qr"][0]
  if q["CLASS"] != CLASSES["IN"]:
    raise UnexpectedDataError("unexpeced CLASS!")   # TODO
  if q["TYPE"] != TYPES["A"]:
    raise UnexpectedDataError("unexpeced TYPE!")    # TODO
  c_name, c_servers, c_pkt = cache_lookup(cache, q["name"])
  if c_name == q["name"] and c_pkt:
    p2 = dns_modify_query_reponse(c_pkt, p["ID"])   # TODO: TTL
    socks[0].sendto(p2, conn["addr"])
    print("responding to {} for {} (cached)"
          .format(conn["addr"], q["name"]))
  else:
    print("query for {} from {} (ID={})"
            .format(q["name"], addr, p["ID"]))
    conn["server"]  = server  = random.choice(c_servers) \
                                if c_servers else random_root_server()
    conn["sock"]    = sock    = S.socket(S.AF_INET, S.SOCK_DGRAM)
    send_query(sock, (server, DEFAULT_PORT), q["name"], p["ID"], False)
    if sock not in socks: socks.append(sock)
                                                                # }}}1

# TODO
def handle_query_reponse(p, addr, conns, socks, cache):         # {{{1
  """handle response to query"""

  # TODO: errors, cleanup, ...

  conn = conns[p["ID"]]; sock = conn["sock"]; q = conn["query"]
  print("response for {} from {} for {} (ID={})"
          .format(q["name"], addr, conn["addr"], p["ID"]))
  if p["flags"]["RCODE"] != 0 or len(p["an"]) > 0:  # done!
    # TODO: caching
    p2 = dns_modify_query_reponse(p["pkt"])
    socks[0].sendto(p2, conn["addr"])
    sock.close(); socks.remove(sock); del conns[p["ID"]]
    print("responding to {} for {} (ID={})"
          .format(conn["addr"], q["name"], p["ID"]))
    if len(p["an"]) > 0:
      cache_response(cache, p["an"][0]["name"], [addr[0]], p["pkt"])
  else:
    names   = [ unpack_dns_labels(x["RDATA"], p["pkt"])[0]
                  for x in p["ns"] ]
    servers = []
    for a in p["ar"]:
      if a["CLASS"] != CLASSES["IN"]: continue
      if a["TYPE"] != TYPES["A"]: continue
      for name in names:
        if a["name"] == name:
          servers.append(S.inet_ntoa(a["RDATA"]))
    if not servers:
      # assume nameserver in other domain; TODO: no cheating?!
      servers = names
    conn["server"] = server = random.choice(servers)
    cache_response(cache, p["ns"][0]["name"], servers)
    send_query(sock, (server, DEFAULT_PORT), q["name"], p["ID"],
               False)
                                                                # }}}1

# TODO
def cache_response(c, name, servers, packet = None):            # {{{1
  if c is None: return
  for label in reversed(name.split(".")):
    if label not in c:
      p = c[label] = dict(tree = {}, servers = [], packet = None,
                          time = 0)
    p = c[label]; c = p["tree"]
  p["servers"] = servers; p["time"] = time.time()
  if not p["packet"] and packet: p["packet"] = PacketWrapper(packet)
                                                                # }}}1

# TODO
def cache_lookup(c, name):                                      # {{{1
  clean_cache(c)  # TODO
  s = []; p = None; n = ""
  if c is None: return n, s, p
  for label in reversed(name.split(".")):
    if label not in c: break
    n = label + ("." + n if n else "")
    s = c[label]["servers"]
    p = c[label]["packet"]
    c = c[label]["tree"]
  return n, s, p and p.p
                                                                # }}}1

# TODO
def clean_cache(c):                                             # {{{1
  if c is None: return
  ttl = c["__TTL__"]; todo = [c]
  while todo:
    d = todo.pop()
    for label in d:
      if label == "__TTL__": continue
      x = d[label]
      if time.time() - x["time"] > ttl:   # TODO: use original TTL?!
        x["servers"] = []; x["packet"] = None
        todo.append(x["tree"])
                                                                # }}}1

def load_cache():                                               # {{{1
  try:
    with open(CACHE_FILE) as f:
      return json.load(f, object_hook = from_json)
  except IOError as e:
    if e.errno != 2: raise
    else: return None   # no such file
  except ValueError:
    return {}
                                                                # }}}1

def save_cache(c):
  with open(CACHE_FILE, "w") as f:
    json.dump(c, f, sort_keys = True, indent = 2,
              separators = (',', ': '), default = to_json)

def send_query(sock, addr, name, ID = None, recurse = True):
  """send DNS query"""
  if ID is None: ID = DEFAULT_ID()
  q = dns_question(name)
  p = dns_query([q], ID = ID, RD = int(bool(recurse)))
  sock.sendto(p, addr)
  return ID

def recv_response(sock, _addr, _ID, timeout):
  """receive DNS query response"""
  f = lambda pkt, _recv_addr: unpack_dns(pkt)
  return recv_reply(sock, timeout, f)

def recv_reply(sock, timeout, f):                               # {{{1
  """receive reply"""

  while timeout > 0:
    t1 = time.time()
    rs, _, _ = select.select([sock], [], [], timeout)
    if rs == []: return TIMEOUT
    for s in rs:
      pkt, recv_addr = s.recvfrom(1024)
      r = f(pkt, recv_addr)
      if r is not None:
        r.update(recv_addr = recv_addr, length = len(pkt))
        return r
    timeout -= (time.time() - t1)
  return TIMEOUT
                                                                # }}}1

def default_nameserver():
  """the default nameserver (if any)"""
  servers = default_nameservers()
  if servers: return servers[0]
  return None

def default_nameservers(resolv_conf = RESOLV_CONF):             # {{{1
  r"""
  get default nameservers from resolv.conf

  >>> import dns as D, tempfile
  >>> n = tempfile.mkstemp()[1]
  >>> d = "domain foo.example.com\nsearch lan.example.com\nnameserver 192.168.1.254\n"
  >>> with open(n, "w") as f:
  ...   f.write(d) and None   # no output
  >>> D.default_nameservers(n)
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
  r"""
  unpack DNS packet

  >>> import binascii as B, dns as D
  >>> d = b"70930100000100000000000003777777066f626675736b0263680000010001"
  >>> p = B.unhexlify(d)
  >>> u = unpack_dns(p)
  >>> u["ID"]
  28819
  >>> sorted(u["flags"].items())
  [('AA', 0), ('QR', 0), ('RA', 0), ('RCODE', 0), ('RD', 1)]
  >>> len(u["qr"])
  1
  >>> sorted(u["qr"][0].items())
  [('CLASS', 1), ('TYPE', 1), ('name', 'www.obfusk.ch')]
  >>> u["an"], u["ns"], u["ar"]
  ([], [], [])

  >>> d = b"398880000001000000020000076578616d706c6503636f6d0000010001c014000200010002a300001401610c67746c642d73657276657273036e657400c014000200010002a30000040162c02bc014000200010002a3000004"
  >>> p = B.unhexlify(d)
  >>> u = unpack_dns(p)
  >>> u["ID"]
  14728
  >>> sorted(u["flags"].items())
  [('AA', 0), ('QR', 1), ('RA', 0), ('RCODE', 0), ('RD', 0)]
  >>> len(u["qr"])
  1
  >>> sorted(u["qr"][0].items())
  [('CLASS', 1), ('TYPE', 1), ('name', 'example.com')]
  >>> len(u["ns"])
  2
  >>> D.unpack_dns_labels(u["ns"][0]["RDATA"], p)[0]
  'a.gtld-servers.net'
  >>> D.unpack_dns_labels(u["ns"][1]["RDATA"], p)[0]
  'b.gtld-servers.net'
  >>> u["ns"][0]["RDATA"] = u["ns"][1]["RDATA"] = None  # only show rest
  >>> sorted(u["ns"][0].items())
  [('CLASS', 1), ('RDATA', None), ('TTL', 172800), ('TYPE', 2), ('name', 'com')]
  >>> sorted(u["ns"][1].items())
  [('CLASS', 1), ('RDATA', None), ('TTL', 172800), ('TYPE', 2), ('name', 'com')]
  >>> u["an"], u["ar"]
  ([], [])
  """

  ID, flag_bits, n_qr, n_an, n_ns, n_ar = \
    struct.unpack("!HHHHHH", pkt[:12])
  qr, an, ns, ar = [], [], [], []
  flags = dict(
    QR    = flag_bits >> 15 & 1, AA = flag_bits >> 10 & 1,
    RD    = flag_bits >>  8 & 1, RA = flag_bits >>  7 & 1,
    RCODE = flag_bits & 0b1111      # TODO: all flags
  )
  qr, offset1 = unpack_dns_qr(n_qr, pkt, 12)
  an, offset2 = unpack_dns_rr(n_an, pkt, offset1)
  ns, offset3 = unpack_dns_rr(n_ns, pkt, offset2)
  ar, offset4 = unpack_dns_rr(n_ar, pkt, offset3)
  return dict(ID = ID, flags = flags, qr = qr, an = an,
                                      ns = ns, ar = ar, pkt = pkt)
                                                                # }}}1

def unpack_dns_qr(n, data, offset = 0):                         # {{{1
  """unpack DNS questions"""

  qr = []
  for i in xrange(n):
    name, o     = unpack_dns_labels(data[offset:], data)
    TYPE, CLASS = struct.unpack("!HH", data[offset+o:offset+o+4])
    offset     += o+4
    qr.append(dict(name = name, TYPE = TYPE, CLASS = CLASS))
  return qr, offset
                                                                # }}}1

def unpack_dns_rr(n, data, offset = 0):                         # {{{1
  """unpack DNS Resource Records"""

  rr = []
  for i in xrange(n):
    name, o     = unpack_dns_labels(data[offset:], data)
    TYPE, CLASS, TTL, RDLENGTH \
                = struct.unpack("!HHiH", data[offset+o:offset+o+10])
    RDATA       = data[offset+o+10:offset+o+10+RDLENGTH]
    offset     += o+10+RDLENGTH
    rr.append(dict(name = name, TYPE = TYPE, CLASS = CLASS,
                   TTL = TTL, RDATA = RDATA))
  return rr, offset
                                                                # }}}1

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

  labels, ptr, offset = [], 0, 0
  while len(data):
    n = b2i(data[0])
    if n == 0:
      if not ptr: offset += 1
      break
    if n >> 6 == 0b11:
      if not ptr: offset += 2       # TODO: MAGIC NUMBER 5
      if ptr >= 5: raise Error("will only follow 5 pointers")
      data, ptr = pkt[(n & 0b111111)+b2i(data[1]):], ptr+1
    else:
      label, data = data[1:n+1], data[n+1:]
      labels.append(b2s(label))
      if not ptr: offset += n+1
  return ".".join(labels), offset
                                                                # }}}!

def dns_modify_query_reponse(p, ID = None):
  """make response non-authoritative (and modify the ID)"""
  ID_ = struct.pack("!H", ID) if ID else p[:2]
  return ID_ + i2b(b2i(p[2:4]) & 0b1111101111111111) + p[4:]

def dns_query(qr, ID = None, **flags):                          # {{{1
  """
  create DNS query

  >>> import binascii as B, dns as D
  >>> q = D.dns_question("www.obfusk.ch")
  >>> p = D.dns_query([q], ID = 0x7093)
  >>> D.b2s(B.hexlify(p))
  '70930100000100000000000003777777066f626675736b0263680000010001'
  """

  if ID is None: ID = DEFAULT_ID()
  fl = dict(QR = 0, RD = 1); fl.update(flags)
  return dns_packet(ID, qr = qr, **fl)
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

# TODO: incomplete
CLASSES = dict(IN = 1)

RCODES = {                                                      # {{{1
  1 : "FORMERR" ,
  2 : "SERVFAIL",
  3 : "NXDOMAIN",
  4 : "NOTIMP"  ,
  5 : "REFUSED" ,
  6 : "YXDOMAIN",
  7 : "YXRRSET" ,
  8 : "NXRRSET" ,
  9 : "NOTAUTH" ,
  10: "NOTZONE" ,
  16: "BADVERS" ,
}                                                               # }}}1

def random_root_server():
  return random.choice(list(ROOT_SERVERS.values()))

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

TIMEOUT = "__timeout__"

def b2i(x):
  """convert bytes to integer"""
  if isinstance(x, int): return x
  return int(binascii.hexlify(x), 16)

def i2b(x, n = 1):
  """convert integer to bytes of length (at least) n"""
  if isinstance(x, bytes): return x
  return binascii.unhexlify(s2b("%0*x" % (n*2,x)))

# TODO
if sys.version_info.major == 2:                                 # {{{1
  def to_json(pyobj):
    if isinstance(pyobj, PacketWrapper):
      return { "__class__": "PacketWrapper",
               "__value__": map(ord, pyobj.p) }
    raise TypeError(repr(pyobj) + " is not JSON serializable")
  def from_json(jsonobj):
    if "__class__" in jsonobj:
      if jsonobj["__class__"] == "PacketWrapper":
        return PacketWrapper("".join(map(chr, jsonobj["__value__"])))
    return jsonobj
else:
  def to_json(pyobj):
    if isinstance(pyobj, PacketWrapper):
       return { "__class__": "PacketWrapper",
                "__value__": list(pyobj.p) }
    raise TypeError(repr(pyobj) + " is not JSON serializable")
  def from_json(jsonobj):
    if "__class__" in jsonobj:
      if jsonobj["__class__"] == "PacketWrapper":
        return PacketWrapper(bytes(jsonobj["__value__"]))
    return jsonobj
                                                                # }}}1

if __name__ == "__main__":
  sys.exit(main(*sys.argv[1:]))

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
