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

def normalize_address(address):
    if address[:2] == '0x':
        address = address[:2]
    return address.lower()

class EthAccount():

    def __init__(self, contract_account):
        self.contract_account = contract_account

#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;
# struct [[eosio::table]] accountcounter {
#     uint64_t                        count;
#     int32_t                         chain_id;
#     EOSLIB_SERIALIZE( accountcounter, (count)(chain_id) )
# };
# typedef eosio::singleton< "global"_n, accountcounter >   account_counter;
    def get_eth_address_count(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global', '', '', '', 1)
        return ret['rows'][0]['count']

    def get_eth_chain_id(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global', '', '', '', 1)
        return ret['rows'][0]['chainid']

#key256_acounter
#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;
# struct [[eosio::table]] key256counter {
#     uint64_t                        count;
#     EOSLIB_SERIALIZE( key256counter, (count) )
# };
#typedef eosio::singleton< "global2"_n, key256counter >   key256_counter;
    def get_total_keys(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global2', '', '', '', 1)
        if ret['rows']:
            return ret['rows'][0]['count']
        return 0

#table ethaccount

#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;

# struct [[eosio::table]] ethaccount {
#     uint64_t                        index;
#     uint64_t                        creator;
#     int32_t                         nonce;
#     std::vector<char>               address;
#     asset                           balance;
#     ethaccount() {
#         address.resize(SIZE_ADDRESS);
#     }
#     uint64_t primary_key() const { return index; }
#     checksum256 by_address() const {
#        auto ret = checksum256();//address;
#        memset(ret.data(), 0, sizeof(checksum256));
#        memcpy(ret.data(), address.data(), SIZE_ADDRESS);
#        return ret;
#     }

#     uint64_t by_creator() const {
#         return creator;
#     }

# typedef multi_index<"ethaccount"_n,
#                 ethaccount,
#                 indexed_by< "byaddress"_n, const_mem_fun<ethaccount, checksum256, &ethaccount::by_address> >,
#                 indexed_by< "bycreator"_n, const_mem_fun<ethaccount, uint64_t, &ethaccount::by_creator> > 
#                 > ethaccount_table;
    def get_address_info(self, address):
        address = normalize_address(address)
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'ethaccount', '', '', '', 100)
        rows = ret['rows']
        for row in rows:
            if row['address'] == address:
                return row
        return None

    def get_address_creator(self, address):
        row = self.get_address_info(address)
        if row:
            return row['creator']

    def get_address_index(self, address):
        row = self.get_address_info(address)
        if row:
            return row['index']

    def get_address_balance(self, address):
        row = self.get_address_info(address)
        if row:
            return row['balance']

    def get_address_nonce(self, address):
        row = self.get_address_info(address)
        if row:
            return row['nonce']

    #addressmap
    #     uint64_t code = current_receiver().value;
    #     uint64_t scope = code;
    #primary_index creator
    # struct [[eosio::table]] addressmap {
    #     uint64_t                        creator;
    #     std::vector<char>               address;
    #     uint64_t primary_key() const { return creator; }
    # }
    def get_account_binded_address(self, account):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'addressmap', account, '', '', 1)
        assert ret['rows'][0]['creator'] == account
        return ret['rows'][0]['address']

#table account_state
# uint64_t code = current_receiver().value;
# scope = creator
# struct [[eosio::table]] account_state {
#     uint64_t                        index;
#     checksum256                     key;
#     checksum256                     value;
#     uint64_t primary_key() const { return index; }
#     checksum256 by_key() const {
#        return key;
#     }
#     EOSLIB_SERIALIZE( account_state, (index)(key)(value) )
# };

# typedef multi_index<"accountstate"_n,
#                 account_state,
#                 indexed_by< "bykey"_n,
#                 const_mem_fun<account_state, checksum256, &account_state::by_key> > > account_state_table;

    def get_value(self, address, key):
        creator = self.get_address_creator(address)
        index = self.get_address_index(address)
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(True, self.contract_account, index, 'accountstate', '', '', '', 100)
        for row in ret['rows']:
            if row['key'] == key:
                return row['key']
        return None

    def get_code(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        if not row:
            return ''
        index = row['index']
        creator = row['creator']
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(True, self.contract_account, creator, 'ethcode', index, '', '', 1)
        if ret['rows']:
            return ret['rows'][0]['code']
        return ''

#     uint64_t code = current_receiver().value;
# scope = creator
# struct [[eosio::table]] ethcode {
#     uint64_t                        index;
#     std::vector<char>               address;
#     vector<char>                    code;
#     uint64_t primary_key() const { return index; }

# typedef multi_index<"ethcode"_n,
#                 ethcode,
#                 indexed_by< "byaddress"_n,
#                 const_mem_fun<ethcode, checksum256, &ethcode::by_address> > > ethcode_table;



provider = LocalProvider()
w3 = Web3(provider)
# my_provider = Web3.IPCProvider('/Users/newworld/dev/uuos2/build/aleth/aleth/dd/geth.ipc')
# w3 = Web3(my_provider)
#print(__file__, 'initialization finished!')
