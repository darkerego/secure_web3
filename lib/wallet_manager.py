from getpass import getpass
from typing import Tuple
import os

import hmac
import json

import base64
import hashlib
import uuid
import web3
from Crypto import Random
from Crypto.Cipher import AES


class JsonWallet:
    def __init__(self, wallet_file):
        self.wallet_file = wallet_file
        self.jw = {'enc_password': None,
                   'salt': None,
                   'enc_wallet': None,
                   'public_address': None,
                   'comment': None}

    def setup(self, encrypted_password: bytes = None,
              salt: bytes = None,
              encrypted_key: bytes = None,
              public_key: str = None,
              comment: str = None):
        # encoded_password =
        self.jw.update({'enc_password': base64.b64encode(encrypted_password).decode()})
        self.jw.update({'salt': base64.b64encode(salt).decode()})
        self.jw.update({'enc_wallet': base64.b64encode(encrypted_key).decode()})
        self.jw.update({'public_address': public_key})
        self.jw.update({'comment': comment})

    def save_wallet(self):
        with open(self.wallet_file, 'w') as f:
            json.dump(obj=self.jw, fp=f)

    def load_wallet(self):
        with open(self.wallet_file, 'r') as f:
            self.jw = json.load(fp=f)
            return base64.b64decode(self.jw.get('enc_password')), base64.b64decode(
                self.jw.get('salt')), base64.b64decode(self.jw.get('enc_wallet')), \
                   self.jw.get('public_address')


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def check_encryption(self, enc, plaintext):
        dec = self.decrypt(enc)
        assert dec == plaintext

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class HasherLib:

    def hash_str(self, password: str) -> Tuple[bytes, bytes]:
        """
        Hash the provided password with a randomly-generated salt and return the
        salt and hash to store in the database.
        """
        salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt, pw_hash

    def check_hash_str(self, salt: bytes, pw_hash: bytes, password: str) -> bool:
        """
        Given a previously-stored salt and hash, and a password provided by a user
        trying to log in, check whether the password is correct.
        """
        return hmac.compare_digest(
            pw_hash,
            hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        )


class WalletManager:
    def __init__(self, wallet_file):
        self.wallet_file = wallet_file
        self.wallet = JsonWallet(wallet_file)
        self.aes = AESCipher
        self.hasher = HasherLib()

    def privkey_to_address(self, key):
        acct = web3.eth.Account.from_key(str(key))
        return acct.address

    def setup_wizard(self):
        password = ''
        # Example usage:
        for x in range(3):
            password: str = getpass('Enter password  >> ')
            confirm_password = getpass('Confirm password >>: ')
            s, p = self.hasher.hash_str(password=password)
            assert self.hasher.check_hash_str(s, p, password)
            assert not self.hasher.check_hash_str(s, p, str(uuid.uuid4().hex))
            private_key = getpass('Enter privkey >> ')
            confirm_key = getpass('Confirm key >> ')
            comment = input('Optional Comment: >> ')
            if private_key == confirm_key:
                self.aes = AESCipher(password)
                enc_key = self.aes.encrypt(private_key)
                try:
                    self.aes.check_encryption(enc_key, private_key)
                except AssertionError:
                    print('[!] Error decrypting, try again.')
                else:
                    print('[+] The wizard successfully configured your wallet.')

                if password == confirm_password:
                    print('Success ... encrypting')

                    self.wallet.setup(encrypted_password=p, salt=s, encrypted_key=enc_key,
                                      public_key=self.privkey_to_address(private_key),
                                      comment=comment)

                    del password, confirm_password, private_key, confirm_key, comment
                    self.wallet.save_wallet()

                    break
                else:
                    print('Keys did not match ...')

    def _decrypt_load_wallet(self):
        """
        Possibly more secure method?
        :return:
        """
        pw = getpass('Unlock wallet >>')
        salt, password, enc_key, address = self.wallet.load_wallet()

        if self.hasher.check_hash_str(password, salt, pw):
            self.aes = AESCipher(pw)
            return self.aes.decrypt(enc=enc_key)
        else:
            return False

    def decrypt_load_wallet(self):
        """
        User friendly method
        :return:
        """
        ret = False
        for x in range(3):
            try:
                ret = self._decrypt_load_wallet()
            except KeyboardInterrupt:
                print('[-] Caught Signal, exit gracefully .. ')
            else:
                if ret:
                    print('[~] Successfully unlocked wallet .. ')
                    break
                else:
                    print('[!] Incorrect password')
            if x+1 == 3:
                print('Max tries exceeded.')
        return ret


if __name__ == '__main__':
    w = WalletManager('.wallet')
    w.setup_wizard()
