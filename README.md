# Secure Web3

### About

<p>
This is a simple, secure command-line wallet for EVM compatible wallets. Additionally, it is a secure framework for developers to manage their private keys with. It contains a setup wizard that encrypts your wallet and saves it into a json file for secure storage. 
I wrote it because I have a lot of web3 projects and I do not like storing private keys in plaintext on disc.
<p>
<b> Use as a wallet</b>
</p>
<p>
Sw3 is a command line wallet which is compatable with any EVM chain. Currently it supports sending both 
eth and erc20 tokens. I will be adding more features in time.
</p>

<pre>
usage: Secure Web3 Cli [-h] [-i INIT_WALLET] [-o [OPEN_WALLET]] [-l] [-n {ethereum,polygon,bsc,aurora,goerli}] [-it IMPORT_TOKEN] [-b] [-r BROADCAST_RAW] [-s {eth,erc20}] [-L]

options:
  -h, --help            show this help message and exit

  Wallet managment options.

  -i INIT_WALLET, --init INIT_WALLET
                        Initialize this new wallet
  -o [OPEN_WALLET], --open [OPEN_WALLET]
                        Unlock a wallet, use default wallet if not specified.
  -l, --lock            Lock all open wallets.
  -n {ethereum,polygon,bsc,aurora,goerli}, --network {ethereum,polygon,bsc,aurora,goerli}

  Wallet configuration options and functions

  -it IMPORT_TOKEN, --import-token IMPORT_TOKEN
                        Add this token to the specified wallet.

  EVM State-Reading functions.

  -b, --balance         Get wallet balance info.

  EVM State-Writing related options.

  -r BROADCAST_RAW, --raw BROADCAST_RAW
                        Load a json tx from this file to sign and broadcast.
  -s {eth,erc20}, --send {eth,erc20}
                        Open interactive shell to send ethereum.
  -L, --legacy          Use legacy gas protocol.


</pre>

<p>
<b>
As a development framework
</b>
</p>

<p>
See main.py for example use.
</p>

### Installation 
<p>
To install with pip:
</p>
pip3 install secure-web3==1.2.7

<p>
You can also install from source by cloning this repo, installing the dependencies in requirements.txt, 
and running `setup.py build`  and then `setup.py install`.
</p>

### Configuration

<p>
secure-web3 expects to find your rpc endpoints in the .env file. It will look for these names:

{network}_http_endpoint
{network}_ws_endpoint

Example:

ethereum_http_endpoint
ethereum_ws_endpoint

</p>
<p>
If you need RPC endpoints, I used to recommend Quicknode. Here is a referal:

https://www.quicknode.com?tap_a=67226-09396e&tap_s=3874015-93e753&utm_source=affiliate&utm_campaign=generic&utm_content=affiliate_landing_page&utm_medium=generic

But now I recommend particle:
https://particle.network. I will adapt this library eventually to include the ability to automatically use particle's api for any supported chain. It supports almost all of them.
</p>

#### If pycryptodome crashes ...
<p>
Run $ pip3 install --upgrade  pycryptodome
</p>

#### If web3 crashes,
<p>
run $pip3 install web3 --upgrade
</p>
<pre>



>> from secure_web3 import sw3
>> manager = sw3.wallet_manager.WalletManager(wallet_file)
>> priv_key = manager.decrypt_load_wallet()

</pre>

### Changelog

- January 28th, 2023 -- Added support for flashbots RPC and private transactions.
