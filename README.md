# Secure Web3

### About

<p>
This is a simple wallet manager for EVM compatible wallets. It contains a setup wizard that encrypts your wallet 
and saves it into a json file for secure storage. I wrote it because I have a lot of web3 projects and I do not like 
storing private keys in plaintext on disc. At the time I wrote it I was not aware of other options like brownie. 
</p>

<pre>
usage: Secure Web3 Cli [-h] [-i INIT_WALLET] [-o [OPEN_WALLET]] [-l] [-n {ethereum,polygon,bsc,aurora}]

options:
  -h, --help            show this help message and exit
  -i INIT_WALLET, --init INIT_WALLET
                        Initialize this new wallet
  -o [OPEN_WALLET], --open [OPEN_WALLET]
                        Unlock a wallet by specifyingan environment variable name, use default wallet if not specified.
  -l, --lock            Lock all open wallets.
  -n {ethereum,polygon,bsc,aurora}, --network {ethereum,polygon,bsc,aurora}

</pre>