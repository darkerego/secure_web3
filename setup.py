from setuptools import setup

setup(
    name='secure_web3',
    version='1.1',
    packages=[''],
    install_requires=['web3', 'pycryptodome'],
    data_files=[('keys', ['keys/default_wallet.json']), ('data', ['data/networks.json'])],
    url='https://github.com/darkerego/secure_web3',
    license='MIT',
    author='darkerego',
    author_email='chevisyoung@gmail.com',
    description='Secure Web3 Wallet and DevEnv'
)
