# Setting up MWC-wallet



## Building your own binary

### Requirements
1. All the [current requirements](https://github.com/mimblewimble/mwc/blob/master/doc/build.md#requirements) of Mwc.
1. [OpenSSL](https://www.openssl.org).
   * macOS with Homebrew:
      ```
      $ brew install openssl # you need to install version 1.1 of openssl for version 1.0.1 or newer of wallet713
      ``` 
   * Linux:
      ```
      $ sudo apt-get install openssl
      ```

### Installation

```
$ git clone https://github.com/mwcproject/mwc-wallet.git
$ cd mwc-wallet
$ cargo build --release
```
MWC-wallet needs to run against a node, you can connect to a local node and a remote node. 
For details about how to install a local node, please refer to the page:[Mwc's Wiki](https://github.com/mimblewimble/docs/wiki/Wallet-User-Guide)

The following steps is to show how to run against a remote node. 
MWC-wallet needs be be initiated first.
```
$ cd target/release
$ ./mwc-wallet init [flags]
```

If you'd like to run against floonet, use:
```
$ cd target/release
$ ./mwc-wallet --floonet init [flags]
```
--help will help to list all the available flags
```
$ ./mwc-wallet --floonet init --help
```

After wallet is initiated, mwc-wallet.toml file will be generated( either in the default ~/.mwc directory or current directory )
Open this file, update the parameter check_node_api_http_addr to the address of the remote node.
The address can contain multiple nodes for failover purpose. There needs be a semicolon in between the addresses.
For example: https://mwc713.floonet.mwc.mw;https://mwc7132.floonet.mwc.mw;https://mwc7133.floonet.mwc.mw;
https://mwc7134.floonet.mwc.mw

Mainnet: mwc713.mwc.mw mwc71362.mwc.mw mwc7133.mwc.mw mwc7134.mwc.mw mwc7135.mwc.mw mwc7136.mwc.mw
Floonet: mwc713.floonet.mwc.mw mwc7132.floonet.mwc.mw mwc7133.floonet.mwc.mw mwc7134.floonet.mwc.mw


api_seed in the .api_seed file(same directory as mwc-wallet.toml file) will also be updated.

