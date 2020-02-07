import os
import json
import web3
from web3 import Web3
from solc import link_code
from pyeoskit import eosapi

from eth_utils import (
    to_dict,
)

keys = {
    '0xb654a7a81e0aeb7721a22f27a04ecf5af0e8a9a3':'0x2a2a401e99b8b032fcb20c320af2bc066222eba7c0496e012200e58caf1bfb5a',
    '0x75852e7970857bd19fe1984d95ced5aa9760d615':'0x40b37416a2e9dbec8216da99393353191fae7ccacee0c57b3ed83391a17389dc',
    '0xf85a43020b1afd50e78dcbbe3b1ac8f4b07a0919':'0x8a30bcfc8638d210ec90799cb298f990ca1fb80bd1cba24e82c044a7e028f19c'
}

from eth_account._utils.transactions import (
    ChainAwareUnsignedTransaction,
    UnsignedTransaction,
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
    strip_signature,
)

from cytoolz import dissoc

def publish_evm_code_old(transaction):
    key = None
#    print(transaction)
    if 'from' in transaction:
        address = transaction['from']
        if address.lower() in keys:
            key = keys[address.lower()]
    
    if not key:
        key = '0x8a30bcfc8638d210ec90799cb298f990ca1fb80bd1cba24e82c044a7e028f19c'
        transaction['from'] = '0xF85A43020B1afD50E78dcBBE3B1aC8F4b07A0919'
    
    transaction['nonce'] = 0
    transaction['gasPrice'] = 1
    transaction['gas'] = 20000000
    #https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    transaction['chainId'] = 1 #Ethereum mainnet
    
    print(transaction)
    signed = web3.eth.Account.sign_transaction(transaction, '0x'+'0'*64)
    print(signed)

    name = 'helloworld11'
    try:
        sender = transaction['from'];
        if sender[:2] == '0x':
            sender = sender[2:]
        args = {'trx': signed.rawTransaction.hex(), 'sender': sender}
        r = eosapi.push_action(name, 'raw', signed.rawTransaction, {name:'active'})
        return r
        res = r['processed']['action_traces'][0]['receipt']['return_value']
#        print(res)
        res = bytes.fromhex(res).decode('utf8')
        res = json.loads(res)
        print(r['processed']['elapsed'])
#        print('++++res:', res)
        return res
    except Exception as e:
        print('++++', e)

def publish_evm_code(transaction):

    transaction['nonce'] = 0
    transaction['gasPrice'] = 1
    transaction['gas'] = 20000000


    sender = transaction['from'];
    if sender[:2] == '0x':
        sender = sender[2:]
    transaction = dissoc(transaction, 'from')
    print(transaction)
    unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction)
    encoded_transaction = encode_transaction(unsigned_transaction, vrs=(0, 0, 0))

    name = 'helloworld11'
    try:
        args = {'trx': encoded_transaction.hex(), 'sender': sender}
        r = eosapi.push_action(name, 'raw', args, {name:'active'})
        return r
        res = r['processed']['action_traces'][0]['receipt']['return_value']
#        print(res)
        res = bytes.fromhex(res).decode('utf8')
        res = json.loads(res)
        print(r['processed']['elapsed'])
#        print('++++res:', res)
        return res
    except Exception as e:
        print('++++', e)
        
def get_code(contract_name):
    circuits_path = '/Users/newworld/dev/tornado-core/build/circuits'
    contract = os.path.join(circuits_path, f'{contract_name}.json')
    contract = open(contract, 'r').read()
    contract = json.loads(contract)
    abi = contract['abi']
    return contract['bytecode']

def gen_contract(bytecode, abi):
    return w3.eth.contract(
        address=Web3.toChecksumAddress('0xb654A7A81E0aeb7721A22F27A04ecf5aF0E8a9A3'),
        bytecode=bytecode,
        abi=abi,
    )


def get_contract(contract_name, library_name=None, library_address=None):
    circuits_path = '/Users/newworld/dev/tornado-core/build/circuits'
    contract = os.path.join(circuits_path, f'{contract_name}.json')
    with open(contract, 'r') as f:
        contract = f.read()
    contract = json.loads(contract)
    abi = contract['abi']
    bytecode = contract['bytecode']
    
    if library_name and library_address:
        bytecode = link_code(bytecode, {library_name: library_address})

    return gen_contract(bytecode, abi)

def get_contract_abi(contract_name):
    circuits_path = '/Users/newworld/dev/tornado-core/build/circuits'
    contract = os.path.join(circuits_path, f'{contract_name}.json')
    with open(contract, 'r') as f:
        contract = f.read()
    contract = json.loads(contract)
    return contract['abi']
    

class LocalProvider(web3.providers.base.JSONBaseProvider):
    endpoint_uri = None
    _request_args = None
    _request_kwargs = None

    def __init__(self, request_kwargs=None):
        self._request_kwargs = request_kwargs or {}
        super(LocalProvider, self).__init__()

    def __str__(self):
        return "RPC connection {0}".format(self.endpoint_uri)

    @to_dict
    def get_request_kwargs(self):
        if 'headers' not in self._request_kwargs:
            yield 'headers', self.get_request_headers()
        for key, value in self._request_kwargs.items():
            yield key, value

    def request_func_(self, method, params):
        if method == 'eth_sendTransaction':
            print('----request_func', method, params)
            res = publish_evm_code(params[0])
            #eth_sendTransaction(*params)
            return {"id":1, "jsonrpc": "2.0", 'result': res}
        elif method == 'eth_call':
            return {"id":0,"jsonrpc":"2.0","result":123}
        elif method == 'eth_estimateGas':
            return {"id":0,"jsonrpc":"2.0","result":88}
        elif method == 'eth_blockNumber':
            return {"id":0,"jsonrpc":"2.0","result":15}
        elif method == 'eth_getBlock':
            result = {'author': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'extraData': '0xdc809a312e332e302b2b313436372a4444617277692f6170702f496e74', 'gasLimit': 3141592, 'gasUsed': 0, 'hash': '0x259d3ac184c567e4e3aa3fb0aa6c89d39dd172f6dad2c7e26265b40dce2f8893', 'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'miner': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'number': 138, 'parentHash': '0x7ed0cdae409d5b785ea671e24408ab34b25cb450766e501099ad3050afeff71a', 'receiptsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'sha3Uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'stateRoot': '0x1a0789d0d895011034cda1007a4be75faee0b91093c784ebf246c8651dbf699b', 'timestamp': 1521704325, 'totalDifficulty': 131210, 'transactions': [], 'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'uncles': []}
            return {"id":0,"jsonrpc":"2.0","result":result}
        elif method == 'eth_getBlockByNumber':
            result = {'author': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'extraData': '0xdc809a312e332e302b2b313436372a4444617277692f6170702f496e74', 'gasLimit': 3141592, 'gasUsed': 0, 'hash': '0x259d3ac184c567e4e3aa3fb0aa6c89d39dd172f6dad2c7e26265b40dce2f8893', 'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'miner': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'number': 138, 'parentHash': '0x7ed0cdae409d5b785ea671e24408ab34b25cb450766e501099ad3050afeff71a', 'receiptsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'sha3Uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'stateRoot': '0x1a0789d0d895011034cda1007a4be75faee0b91093c784ebf246c8651dbf699b', 'timestamp': 1521704325, 'totalDifficulty': 131210, 'transactions': [], 'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'uncles': []}
            return {"id":0,"jsonrpc":"2.0","result":result}
        elif method == 'eth_blockNumber':
            return {"id":0,"jsonrpc":"2.0","result":'100'}

    def request_func(self, web3, outer_middlewares):
        '''
        @param outer_middlewares is an iterable of middlewares, ordered by first to execute
        @returns a function that calls all the middleware and eventually self.make_request()
        '''
        return self.request_func_
    
    def get_request_headers(self):
        return {
            'Content-Type': 'application/json',
            'User-Agent': construct_user_agent(str(type(self))),
        }

def get_eth_address_info(contract, eth_addr):
    if eth_addr[:2] == '0x':
        eth_addr = eth_addr[2:]
    args = eosapi.pack_args(contract, 'getaddrinfo', {'address':eth_addr})
    ret = eosapi.call_contract(contract, 'getaddrinfo', args.hex())
    args = ret['results']['output']
    ret = eosapi.unpack_args(contract, 'addrinfo', bytes.fromhex(args))
    return json.loads(ret)

provider = LocalProvider()
w3 = Web3(provider)
# my_provider = Web3.IPCProvider('/Users/newworld/dev/uuos2/build/aleth/aleth/dd/geth.ipc')
# w3 = Web3(my_provider)
#print(__file__, 'initialization finished!')
