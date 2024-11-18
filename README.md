# DHTd

A standalone [Kademlia DHT](https://en.wikipedia.org/wiki/Kademlia) (Distribute Hash Table) to connect to the mainline BitTorrent network.

A Distributed Hash Table (DHT) is a distributed system storing key/value pairs used by BitTorrent clients to find peers. DHTd can be used in the same way to find the IP address of other instances in a decentralized way without any authentication. Or you can use it as a bootstrap node.

Otherwise you can think of it as a [Tamagotchi](https://en.wikipedia.org/wiki/Tamagotchi) for people who are into decentralized networks. :-)

Features:

* small at 110KB
* announce and lookup for hashes
* local peer discovery
* run as bootstrap node
* scripting capabilities
* only libc as dependency
* available for OpenWrt

## Quick Start

### Compile

Compilation is rather simple:

```
$ git clone https://github.com/mwarning/dhtd.git
$ cd dhtd
$ make
[...]
$ ./build/dhtd -h
```

(The `$` is the terminal prompt, it is included here to distinguish commands from program output)

### Run

Run DHTd in background:

```
$ dhtd --daemon --peer bttracker.debian.org:6881 --peer router.bittorrent.com:6881
```

Example output after a few minutes:

```
$ dhtd-ctl status
DHTd 1.0.0 ( cli debug lpd )
DHT id: 24e56b174415846be9050d628e8d8c0eda42de96
DHT uptime: 120d6h
DHT listen on: IPv4+IPv6 / device: <any> / port: 6881
DHT nodes: 1090 IPv4 (402 good), 373 IPv6 (349 good)
DHT storage: 280 entries with 648 addresses
DHT searches: 0 IPv4 (0 done), 0 IPv6 active (0 done)
DHT announcements: 0
DHT blocklist: 3
DHT traffic: 24.6 G, 6.8 K/s (in) / 68.5 G, 2.5 K/s (out)
```

Start a search:

```
$ dhtd-ctl search 6f84758b0ddd8dc05840bf932a77935d8b5b8b93
Search started.
```
(the id is from a magnet link of a Debian Linux torrent file)

After a few seconds:

```
$ dhtd-ctl results 6f84758b0ddd8dc05840bf932a77935d8b5b8b93
[2a01:e0a:ea:d9d0::1]:24007
[2a01:e0a:5c4:f490::1]:26915
[2001:470:8:62b:c41a:db05:69db:bb]:59863
[2001:bc8:32d7:25e::42]:51413
[2003:d6:af28:9200:dea6:32ff:fec4:6592]:50476
[2003:e6:2f01:8400::65e]:63746
[2003:e6:2f01:8400:6a6:6b4b:8433:95dd]:63746
[2003:f6:3f2b:3300::1]:51413
[2601:18d:8d7f:e566:beae:c5ff:fe66:ec70]:6881
[2603:8001:4000:6d07:549d:1d6a:9b33:b14f]:38934
```

Note:
 - Searches/Results are discarded after about 62 minutes.
 - You cannot search for the id of the node itself, only ids that someone announced.
 - Use `lookup` to start/continue a search and also print out results.
 - Use `--execute <file>` command line argument to execute a script for each result.

## Command Line Arguments

Startup command line arguments for `dhtd`.

* `--announce` *id*[:*port*]  
  Announce a id and optional port.  
  This option may occur multiple times.
* `--peerfile` *file*  
  Import/Export peers from and to a file.
* `--peer` *address*  
  Add a static peer address.  
  This option may occur multiple times.
* `--execute` *file*  
  Execute a script for each result.
* `--port` *port*  
  Bind DHT to this port.  
  Default: 6881
* `--config` *file*  
  Provide a configuration file with one command line  
  option on each line. Comments start after '#'.
* `--ifname` *interface*   
  Bind to this interface.  
  Default: *any*
* `--daemon`, `-d`  
  Run the node in background.
* `--verbosity` *level*  
  Verbosity level: quiet, verbose or debug.  
  Default: verbose
* `--user` *user*  
  Change the UUID after start.
* `--pidfile` *file*  
  Write process pid to a file.
* `--ipv4`, `-4`, `--ipv6`, `-6`  
  Enable IPv4 or IPv6 only mode.  
  Default: IPv4+IPv6
* `--lpd-disable`  
  Disable multicast to discover local peers.
* `--cli-disable-stdin`  
  Disable the local control interface.
* `--cli-path` *path*  
  Bind the remote control interface to this unix socket path.  
  Default: /tmp/dhtd.sock
* `--help`, `-h`  
  Print this help.
* `--version`, `-v`  
  Print program version.

## Command Line Interface

List of commands that can be send to a running `dhtd` instance via the command line control interface `dhtd-ctl`.

* `status`  
  The current state of this node.
* `lookup <id>`  
  Start search and print results.
* `search <id>`  
  Start a search for announced values.
* `results <id>`  
  Print the results of a search.
* `announce-start <id>[:<port>]`  
  Start to announce an id along with a network port.
* `announce-stop <id>`  
  Stop the announcement.
* `searches`  
  Print a list of all searches. They expire after 62min.
* `announcements`  
  Print a list of all announcements.
* `peer <address>:<port>`  
  Add a peer by address.
* `constants|blocklist|peers|buckets|storage`  
  Print various internal data.

Legend:

`<id>` 20 bytes as hexadecimal string

`<port>` Network port number between 1-65536

`<address>` IPv4 or IPv6 address

## License

MIT/X11

## Authors

* DHTd: Moritz Warning (http://github.com/mwarning/dhtd)
* Kademlia DHT: Juliusz Chroboczek (https://github.com/jech/dht)

## Links

* [kademlia-dht](https://github.com/quarterblue/kademlia-dht) standalone DHT implementation in Rust
* Kademlia DHT formal [specification](http://maude.sip.ucm.es/kademlia/files/pita_kademlia.pdf)
