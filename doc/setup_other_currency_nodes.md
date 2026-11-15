> Historical secondary-chain test setup. It depends on the optional wallet `swaps` feature. Old upstream versions, public services and example RPC credentials are not current deployment instructions; the broad RPC bind/allow settings below are unsuitable for an exposed host. Use a dedicated test environment and the selected node software’s current documentation.

Instructions for setting up bitcoin node and electrumx server. This instruction can be extended to setting up nodes for other types of currencies.


-- starting bitcoin node:
bin/bitcoind -txindex -testnet&

bitcoin.conf:
testnet=1
txindex=1
rpcpassword=core
rpcuser=bitcoin



gen=1
#rcpallowip=127.0.0.1
#rcpallowip=192.168.2.6   # This is the other machine
rpcallowip=0.0.0.0/0

[test]
rpcport=18332
rpcbind=0.0.0.0

-- set up leveldb
sudo apt-get install libsnappy-dev
export VER="1.20"
wget https://github.com/google/leveldb/archive/v${VER}.tar.gz
tar xvf v${VER}.tar.gz
rm -f v${VER}.tar.gz
cd leveldb-${VER}
make (may require doing: sudo apt-get install build-essential libssl-dev libffi-dev python-dev)
sudo scp -r out-static/lib* out-shared/lib* "/usr/local/lib"
cd include
sudo scp -r leveldb /usr/local/include
sudo ldconfig

-- making default python3 to upgrade to python3.7
sudo apt update -y
sudo apt install python3.7
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 1
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 2
sudo update-alternatives --config python3 (select the wanted number and hit return)
sudo rm /usr/bin/python3
sudo ln -s python3.7 /usr/bin/python3

-- install more supportive packages
python3.7 -m pip install --upgrade pip setuptools wheel
python3.7 -m pip install --upgrade aiohttp pylru leveldb plyvel aiorpcx ecdsa

-- electrumx startup script:
#!/bin/sh
 
ulimit -n 5000
export DB_DIRECTORY=/home/ubuntu/electrumx_db
export DAEMON_URL=http://bitcoin:core@127.0.0.1:18332
export COIN=BitcoinSegwit
export NET=testnet
export SERVICES=tcp://0.0.0.0:8000

./electrumx_server > /tmp/electrumx.stdout 2> /tmp/electrumx.stderr &