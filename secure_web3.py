#!/usr/bin/env python3
import argparse
import os
import uuid

import dotenv
import web3
from web3.middleware import geth_poa_middleware

import secure_web3.lib.style
from secure_web3.lib import abi_lib
from secure_web3.lib.wallet_manager import WalletManager


class SecureWeb3:
    def __init__(self, wallet_file=None, network='ethereum'):
        dotenv.load_dotenv()
        self.endpoint = None
        self.token_abi = None
        self.account = None
        self._print = secure_web3.lib.style.PrettyText(0)
        self.wallet_file = wallet_file
        self.network = network
        self.w3 = self.setup_w3()

    def setup_w3(self):
        """
        Configure the web3 rpc endpoint object. Place any chain specific variables here.
        :return: web3.Web3()
        """
        w3_endpoint = os.environ.get(f'{self.network}_http_endpoint')
        self.w3 = web3.Web3(web3.HTTPProvider(w3_endpoint))
        if self.w3.isConnected:
            self._print.good(f"Connected to chain: {self.w3.eth.chain_id}")
        else:
            self._print.error(f'Web3 could connect to remote endpoint: {w3_endpoint}')
        self.token_abi = secure_web3.lib.abi_lib.EIP20_ABI
        if self.network == 'polygon':
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        elif self.network == 'bsc':
            self.token_abi = secure_web3.lib.abi_lib.BEP_ABI
            # self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            self._print.warning('Connected to BSC, which has not been tested very well yet.')
        self._print.good(f'Web3 connected to chain: {self.w3.eth.chain_id}')
        return self.w3

    def load_wallet(self):
        """
        Load the wallet manager and decrypt the wallet.
        :return:
        """
        if not self.wallet_file:
            self.wallet_file = os.environ.get('default_wallet_location')
        w = WalletManager(self.wallet_file)
        # w.setup_wizard()
        self.account = web3.Account.from_key(w.decrypt_load_wallet())
        if self.account:
            # overwrite in memory
            w = uuid.uuid4().hex
            del w
            return True
        return False

    def configure_wallet(self):
        """
        Launch the setup wizards and store the encrypted wallet.
        :return:
        """
        w = WalletManager(self.wallet_file)
        w.setup_wizard()
        w = uuid.uuid4().hex
        del w

    @property
    def web3(self):
        """
        Place logic for using different endpoints in different scenarios here.
        :return:
        """
        return self.w3

    def switch_network(self, network_name, poa=False):
        """
        Switch the chain.
        :param network_name:
        :param poa:
        :return:
        """
        endpoint = os.environ.get(f'infura_{network_name}_endpoint')
        if not endpoint:
            self._print.error('Could not find network, is it configured?')
            return
        w3 = web3.Web3(web3.HTTPProvider(endpoint))
        if network_name == 'polygon':
            poa = True
        if poa:
            w3.middleware_onion.inject(geth_poa_middleware)
        if w3.isConnected():
            self._print.good(f'Successfully switched to {network_name}')
        else:
            self._print.error(f'Web3 could not connect to endpoint at {endpoint}')


if __name__ == '__main__':
    args = argparse.ArgumentParser('Secure Web3 Cli')
    args.add_argument('-i', '--init', dest='init_wallet', type=str, nargs=1,
                      default=None, help='Initialize this new wallet')
    args.add_argument('-o', '--open', dest='open_wallet', type=str, default=None,
                      nargs='?', help='Unlock a wallet by specifying'
                                      'an environment variable name, '
                                      'use default wallet if not specified.')
    args.add_argument('-l', '--lock', dest='lock_wallet', action='store_true',
                      help='Lock all open wallets.')
    args.add_argument('-n', '--network', type=str, default='ethereum',
                      choices=['ethereum', 'polygon', 'bsc', 'aurora'])
    args = args.parse_args()
    dotenv.load_dotenv()

    if args.init_wallet:
        print(f'[*] Configuring new wallet "{args.init_wallet[0]}" ... ')
        manager = WalletManager(args.init_wallet[0])
        manager.setup_wizard()
        exit(0)
    if not args.open_wallet:
        wallet_file = os.environ.get('default_wallet_location')
    else:
        wallet_file = args.open_wallet
    print(f'[*] Opening wallet "{wallet_file}" ... ')
    manager = WalletManager(wallet_file)
    priv_key = manager.decrypt_load_wallet()
    # Do something with private key ...
    # print(priv_key)
    print('[+] Successfully unlocked wallet!')
