import sys
import json
from pyeoskit import eosapi

import evm
from evm import EthAccount
from evm import get_eth_address_info, w3
import rlp
import hashlib
from eth_utils import keccak
import logging
from solcx import compile_source, compile_files


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(lineno)d %(module)s %(message)s')

logger=logging.getLogger(__name__)


from init import *

eosapi.set_node('http://127.0.0.1:8888')

config.main_token='EOS'

priv_keys = [
    '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3',#EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV
    '5JEcwbckBCdmji5j8ZoMHLEUS8TqQiqBG1DRx1X9DN124GUok9s',#EOS61MgZLN7Frbc2J7giU7JdYjy2TqnfWFjZuLXvpHJoKzWAj7Nst
    '5JbDP55GXN7MLcNYKCnJtfKi9aD2HvHAdY7g8m67zFTAFkY1uBB',#EOS5JuNfuZPATy8oPz9KMZV2asKf9m8fb2bSzftvhW55FKQFakzFL
    '5K463ynhZoCDDa4RDcr63cUwWLTnKqmdcoTKTHBjqoKfv4u5V7p',#EOS8Znrtgwt8TfpmbVpTKvA2oB8Nqey625CLN8bCN3TEbgx86Dsvr
    '5KH8vwQkP4QoTwgBtCV5ZYhKmv8mx56WeNrw9AZuhNRXTrPzgYc',#EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV
    '5KT26sGXAywAeUSrQjaRiX9uk9uDGNqC1CSojKByLMp7KRp8Ncw',#EOS8Ep2idd8FkvapNfgUwFCjHBG4EVNAjfUsRRqeghvq9E91tkDaj
]
for priv_key in priv_keys:
    wallet.import_key('test', priv_key)

db.reset()
evm.set_chain_id(1)


main_account = 'helloworld11'
test_account = 'helloworld12'


try:
    vm_abi = open('/Users/newworld/dev/eos-with-evm/externals/aleth/evm4eos/ethereum_vm.abi', 'rb').read()
    vm_code = open('/Users/newworld/dev/eos-with-evm/build/externals/aleth/evm4eos_contract/ethereum_vm.wasm', 'rb').read()
    r = eosapi.publish_contract('helloworld11', vm_code, vm_abi, vmtype=0, vmversion=0, sign=True, compress=1)
    print(r['processed']['elapsed'])
except Exception as e:
    print(e)

a = {
    "account": main_account,
    "permission": "active",
    "parent": "owner",
    "auth": {
        "threshold": 1,
        "keys": [
            {
                "key": "EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV",
                "weight": 1
            },
        ],
        "accounts": [{"permission":{"actor":main_account,"permission":"eosio.code"},"weight":1}],
        "waits": []
    }
}
r = eosapi.push_action('eosio', 'updateauth', a, {main_account:'owner'})


a = EthAccount(main_account)

args = {'chainid': 1}
try:
    r = eosapi.push_action(main_account, 'setchainid', args, {main_account:'active'})
    print('++++console:', r['processed']['action_traces'][0]['console'])
    print(r['processed']['elapsed'])
except Exception as e:
    print(e)


eth_address = a.get_binded_address(test_account)
if not eth_address:
    args = {'account': test_account, 'text': 'hello,world'}
    try:
        r = eosapi.push_action(main_account, 'create', args, {test_account:'active'})
        eth_address = r['processed']['action_traces'][0]['console']
        print('eth address:', eth_address)
        print(r['processed']['elapsed'])
    except Exception as e:
        if hasattr(e, 'response'):
            parsed = json.loads(e.response)
            print('+++error:\n', json.dumps(parsed, indent=4))
        else:
            print(e)
        sys.exit(-1)
    assert eth_address == a.get_binded_address(test_account)

    assert a.get_balance(eth_address) == 0.0
    assert a.get_nonce(eth_address) == 1


#verify eth address
e = rlp.encode([test_account, 'hello,world'])
h = keccak(e)
print(h[12:].hex(), eth_address)
assert h[12:].hex() == eth_address

# Deposit Test
balance = a.get_balance(eth_address)
logger.info(('++++balance:', balance))
r = eosapi.transfer(test_account, main_account, 10.0, 'deposit')

assert a.get_balance(eth_address) == balance + 10.0

### Withdraw test
args = {'account': test_account, 'amount': '1.0000 SYS'}
try:
    eos_balance = eosapi.get_balance(test_account)
    eth_balance = a.get_balance(eth_address)
    
    r = eosapi.push_action(main_account, 'withdraw', args, {test_account:'active'})
    print('++++console:', r['processed']['action_traces'][0]['console'])
    print(r['processed']['elapsed'])

    assert eth_balance - 1.0 == a.get_balance(eth_address)
    assert eos_balance + 1.0 == eosapi.get_balance(test_account)
except Exception as e:
    print(e)

#Overdraw test

eth_balance = a.get_balance(eth_address)
logger.info(('++++eth_balance:', eth_balance))
args = {'account': test_account, 'amount': '%.4f SYS'%(eth_balance+0.1,)}
logger.info(('++++args:', args))
try:
    r = eosapi.push_action(main_account, 'withdraw', args, {test_account:'active'})
    print('++++console:', r['processed']['action_traces'][0]['console'])
    #should not go here
    assert 0
except Exception as e:
    assert eth_balance == a.get_balance(eth_address)
    e = json.loads(e.response)
    assert e['error']['details'][0]['message'] == "assertion failure with message: balance overdraw!"


#test deploy evm contract

evm.set_current_account(test_account)

greeter = open('greeter.sol', 'r').read()
def compile(contract_source_code, main_class):
    compiled_sol = compile_source(contract_source_code) # Compiled source code
    contract_interface = compiled_sol[main_class]

    return contract_interface

nonce = a.get_nonce(eth_address)
e = rlp.encode([bytes.fromhex(eth_address), nonce])
h = keccak(e)
expected_address = h[12:].hex()


main_class = '<stdin>:Greeter'
contract_source_code = greeter
contract_interface = compile(contract_source_code, main_class)
bytecode = contract_interface['bin']
abi = contract_interface['abi']

Greeter = w3.eth.contract(abi=abi, bytecode=bytecode)
ret = Greeter.constructor().transact({'from': eth_address})
logger.info(("+++++ret:", ret))

logs = ret['processed']['action_traces'][0]['console']
logs = bytes.fromhex(logs)
logs = rlp.decode(logs)
contract_address = logs[0].hex()

assert expected_address == contract_address
assert a.get_nonce(eth_address) == nonce + 1

#test get contract code
code = a.get_code(contract_address)
# logger.info(code)
# logger.info(logs[1].hex())
assert code == logs[1].hex()

# contract_address = w3.toChecksumAddress(output['new_address'])
# print('+++contract_address:', contract_address)



print('Done!')

