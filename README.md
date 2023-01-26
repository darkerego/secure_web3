# Secure Web3

### About

<p>
This is a simple, secure command-line wallet for EVM compatible wallets. Additionally it is a secure framework for developers to manage their private keys with. It contains a setup wizard that encrypts your wallet and saves it into a json file for secure storage. I wrote it because I have a lot of web3 projects and I do not like storing private keys in plaintext on disc.

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
