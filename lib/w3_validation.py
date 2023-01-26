from web3 import Web3
from web3.exceptions import BadFunctionCallOutput
from eth_utils import to_checksum_address


def validate_addr(addr):
    try:
        to_checksum_address(addr)
    except ValueError:
        return False
    return True


def valid_contract(w3: Web3, addr):
    try:
        assert w3.eth.getCode(addr).hex() != '0x'
    except AssertionError:
        return False
    return True


def valid_token(token):
    try:
        token.functions.balanceOf(token.address).call()
    except BadFunctionCallOutput:
        return False
    else:
        return True