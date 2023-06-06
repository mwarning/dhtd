# DHTd

Run a [Kademlia DHT](https://en.wikipedia.org/wiki/Kademlia) (Distribute Hash Table) to connect with the BitTorrent network and announce identifiers and query them from the command line.

DHTd was created to let nodes of community networks find each other in order to use the Internet as a backbone infrastructure.

Supported are a command line interface and local peer discovery.

## Quick Start

### Compile

Compilation is rather simple:

```
$ git clone https://github.com/mwarning/dhtd.git
$ cd dhtd
$ make
$ cd build
$ ./dhtd -h
```

(The `$` is the terminal prompt, it is included here to distinguish commands from program output)

### Run

Run DHTd:

```
$ dhtd --daemon --peer bttracker.debian.org:6881 --peer router.bittorrent.com:6881
```

Example output after a few minutes:

```
$ dhtd-ctl status
DHTd v1.0.0 ( cmd debug lpd )
DHT id: 787be1061449d204b4c9ae8fbf94d77a1c942615
DHT listen on: IPv4+IPv6 / <any>
DHT nodes: 128 IPv4 (102 good), 128 IPv6 (45 good)
DHT storage: 0 (max 16384) entries with 0 addresses (max 2048)
DHT searches: 0 active, 0 completed (max 1024)
DHT announcements: 0
DHT blacklist: 0 (max 10)
```

Start a query:

```
$ dhtd-ctl search 6f84758b0ddd8dc05840bf932a77935d8b5b8b93
Search started.
```
(the id is from a magnet link of a Debian Linux torrent file)

After a few seconds:

```
$ dhtd-ctl search 6f84758b0ddd8dc05840bf932a77935d8b5b8b93
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

Or use the `--execute <file>` command line argument to execute a script for each result.

## Command Line Arguments

* `--search` *hash*  
  Search for a hash.  
  This option may occur multiple times.
* `--announce` *hash*:*port*  
  Announce a hash and port.  
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
* `--cmd-disable-stdin`  
  Disable the local control interface.
* `--cmd-path` *path*  
  Bind the remote control interface to this unix socket path.  
  Default: /tmp/dhtd.sock
* `--help`, `-h`  
  Print this help.
* `--version`, `-v`  
  Print program version.

## License

MIT/X11

## Authors

* DHTd: Moritz Warning (http://github.com/mwarning/dhtd)
* Kademlia DHT: Juliusz Chroboczek (https://github.com/jech/dht)
