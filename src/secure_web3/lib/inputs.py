from eth_utils import to_checksum_address
from secure_web3.lib import w3_validation
from secure_web3.lib import style
s = style.PrettyText(1)


def get_dest_addr():
    while True:
        destination = input("Destination Address >> ")
        if w3_validation.validate_addr(destination):
            return to_checksum_address(destination)
        s.error(f'Invalid address: "{destination}"')


def confirmation(prompt='Confirm? y/n >> '):
    try:
        confirm_yn = input(prompt)
    except KeyboardInterrupt:
        s.warning('User canceled action')
    else:
        if confirm_yn.lower() in ['yes', 'y']:
            return True
        return False

