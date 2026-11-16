> Historical ElectrumX setup for optional swap testing. Version pins and service availability are not validated by a wallet source audit. See [wallet setup](../setup.md) for enabling the `swaps` feature.

# Background #

This document explaining how to install Electrum X server on Ubuntu 18.04.

The setup will have a single install that will be able to index multiple Coins in different processes.

Every coin will have the different DB location.

# Data location #

we need to know the location of the DB.

export ELECTRUM_DB=<db_path>

# Prerequisites

Python
You will need python 3.7+. You can probably use programs like apt to install it, but that is beyond the scope of this document. You will also need python3-pip to be installed. On debian based systems that can be done with the following command:

```# apt install python3-pip```

You may need to install more supportive Python packages:
```
python3.7 -m pip install --upgrade pip setuptools wheel
python3.7 -m pip install --upgrade aiohttp pylru leveldb plyvel aiorpcx ecdsa
```
Database
You can choose between LevelDB or RocksDB. To install LevelDB:
```
sudo apt-get install libsnappy-dev
export VER="1.20"
wget https://github.com/google/leveldb/archive/v${VER}.tar.gz
tar xvf v${VER}.tar.gz
rm -f v${VER}.tar.gz
cd leveldb-${VER}
make (may first require doing: sudo apt-get install build-essential libssl-dev libffi-dev python-dev)
sudo scp -r out-static/lib* out-shared/lib* "/usr/local/lib"
cd include
sudo scp -r leveldb /usr/local/include
sudo ldconfig
```

# Installation

Cleanup prev electrum instance. We don't want to use update, instead we want to install all package that might be needed. 
```
cd
rm -rf electrumx-installer
sudo rm /usr/local/bin/electrumx_server
```

Installing with installer
```
git clone https://github.com/bauerj/electrumx-installer.git
cd electrumx-installer

sudo ./install.sh -d $ELECTRUM_DB -v --leveldb --electrumx-git-url https://github.com/kyuupichan/electrumx.git --electrumx-git-branch altcoin
```
During installation you might hit the Python issue, ElectrumX requre 3.7 version. 
Here is a help  https://tech.serhatteker.com/post/2019-09/upgrade-python37-on-ubuntu18/

Because install was as sudo, $ELECTRUM_DB dir has wrong credentials. 

```
sudo chown `whoami`:`id -g` $ELECTRUM_DB
```

Checking install:
```
> which electrumx_server
/usr/local/bin/electrumx_server

> ls /usr/local/lib/python3.7/dist-packages/electrumx/
__init__.py  lib  __pycache__  server
```

Now check the coins that your ElectrumX is supporting:
```
cat /usr/local/lib/python3.7/dist-packages/electrumx/lib/coins.py | grep ' NAME '
```
If your coin is there, you are good go

# Creating Script for a Specific coin #

We are almost ready to to start.

Because ElectumX getting it's settings through the environment variables, 
we better to have a script for every coin that we want to index. 

The script can look like this. Note, **Please create separate script for different coins. So it will be easy to start them.**

```
#!/bin/bash

# Please specify your Coin Here.
export COIN_NAME=BitcoinCashABC

# That what Electrum X is required
export DB_DIRECTORY=$ELECTRUM_DB/$COIN_NAME
export DB_ENGINE=leveldb
export COIN=$COIN_NAME
export NET=mainnet
# Address of the Node
export DAEMON_URL=http://user:password@host:port
export SERVICES=tcp://0.0.0.0:8000
export CACHE_MB=300

# Port thet electrum will listen
TCP_PORT=8000

echo "Starting Electum X server"
electrumx_server
```

The output should looks like
```
INFO:electrumx:ElectrumX server starting
INFO:electrumx:logging level: INFO
INFO:Controller:Python version: 3.7.9 (default, Aug 18 2020, 06:22:45)  [GCC 7.5.0]
INFO:Controller:software version: ElectrumX 1.15.0
INFO:Controller:aiorpcX version: 0.18.4
INFO:Controller:supported protocol versions: 1.4-1.4.2
INFO:Controller:event loop policy: None
INFO:Controller:reorg limit is 200 blocks
INFO:Daemon:daemon #1 at 18.204.230.14:8332/ (current)
INFO:DB:switching current directory to /home/electrumx/db/
INFO:DB:using leveldb for DB backend
INFO:DB:opened UTXO DB (for sync: True)
INFO:DB:UTXO DB version: 8
INFO:DB:coin: BitcoinCashABC
INFO:DB:network: mainnet
INFO:DB:height: 220,569
INFO:DB:tip: 00000000000003a12d21614347a2c977beefd0222fbb7f05991b721b6ac0c054
INFO:DB:tx count: 12,557,436
INFO:DB:flushing DB cache at 1,200 MB
INFO:DB:sync time so far: 40m 53s
INFO:History:history DB version: 1
INFO:History:flush count: 12
INFO:Prefetcher:catching up to daemon height 649,098 (428,529 blocks behind)
INFO:LTORBlockProcessor:our height: 220,579 daemon: 649,098 UTXOs 1MB hist 1MB
```

To stop electrumx_server you need to press Ctrl-C

```
^CWARNING:Controller:received SIGINT signal, initiating shutdown
INFO:Controller:shutting down
INFO:Prefetcher:cancelled; prefetcher stopping
INFO:LTORBlockProcessor:flushing to DB for a clean shutdown...
INFO:DB:flushed filesystem data in 0.06s
INFO:History:flushed history in 0.6s for 214,723 addrs
INFO:DB:flushed 846 blocks with 296,676 txs, 126,258 UTXO adds, 97,594 spends in 0.4s, committing...
INFO:DB:flush #13 took 1.6s.  Height 221,415 txs: 12,854,112 (+296,676)
INFO:DB:tx/sec since genesis: 5,062, since last flush: 3,469
INFO:DB:sync time: 42m 19s  ETA: 1d 14h 04m
INFO:Controller:shutdown complete
INFO:electrumx:ElectrumX server terminated normally
```

# TO DO

To make it better, we can do autostart for all servers and we can add watchdog that will monitor if all Servers are online.

