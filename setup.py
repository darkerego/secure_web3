from setuptools import setup

setup(
    name='secure_web3',
    version='1.2.7',
    packages=['secure_web3'],
    install_requires=['web3', 'pycryptodome', 'python-dotenv', 'eth-utils', 'colored', 'pycrypto'],
    package_dir={"": "src"},
    include_package_data=True,
    data_files=[('', ['src/secure_web3/keys/default_wallet.json', 'src/secure_web3/data/networks.json'])],
    url='https://github.com/darkerego/secure_web3',
    license='MIT',
    author='darkerego',
    author_email='chevisyoung@gmail.com',
    description='Secure Web3 Wallet and DevEnv'
)
