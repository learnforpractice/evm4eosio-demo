import os
import json
import web3
from web3 import Web3
from solc import link_code
import rlp
from eth_account._utils.transactions import (
    ChainAwareUnsignedTransaction,
    UnsignedTransaction,
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
    strip_signature,
)

from eth_account.account import Account

from eth_utils import (
    to_dict,
)

from cytoolz import dissoc
from pyeoskit import eosapi

keys = {
#     'b654a7a81e0aeb7721a22f27a04ecf5af0e8a9a3':'2a2a401e99b8b032fcb20c320af2bc066222eba7c0496e012200e58caf1bfb5a',
#     '75852e7970857bd19fe1984d95ced5aa9760d615':'40b37416a2e9dbec8216da99393353191fae7ccacee0c57b3ed83391a17389dc',
#     'f85a43020b1afd50e78dcbbe3b1ac8f4b07a0919':'8a30bcfc8638d210ec90799cb298f990ca1fb80bd1cba24e82c044a7e028f19c',
#     '2c7536e3605d9c16a7a3d7b1898e529396a65c23':'4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
}

g_chain_id = 1
g_current_account = None
g_contract_name = None

def set_chain_id(id):
    global g_chain_id
    g_chain_id = id

def set_current_account(account):
    global g_current_account
    g_current_account = account

def set_contract_name(account):
    global g_contract_name
    g_contract_name = account

def publish_evm_code(transaction):
    global g_chain_id
    global g_current_account
    
    transaction['nonce'] = 0
    transaction['gasPrice'] = 1
    transaction['gas'] = 20000000
#    transaction['chainId'] = chain_id #Ethereum mainnet
#     print(transaction)
    sender = transaction['from'];
    if sender[:2] == '0x':
        sender = sender[2:]
    sender = sender.lower()
    if sender in keys:
        priv_key = key_maps[sender]
        encoded_transaction = Account.sign_transaction(transaction, priv_key)   
        encoded_transaction = encoded_transaction.rawTransaction.hex()[2:]
    else:
        transaction = dissoc(transaction, 'from')
        unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction)
        encoded_transaction = encode_transaction(unsigned_transaction, vrs=(g_chain_id, 0, 0))
        encoded_transaction = encoded_transaction.hex()

    if g_current_account:
        account_name = g_current_account
    else:
        account_name = 'helloworld11'
    
    if g_contract_name:
        contract_name = g_contract_name
    else:
        contract_name = 'helloworld11'
    
    try:
        args = {'trx': encoded_transaction, 'sender': sender}
        r = eosapi.push_action(contract_name, 'raw', args, {account_name:'active'})
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
#             print('----request_func', method, params)
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
