import sys
import json
import evm
from evm import Eth, EthAccount
from evm import w3
import rlp
import hashlib
from eth_utils import keccak
import logging
from solcx import compile_source, compile_files
import unittest
# from threading import RLock
from multiprocessing import RLock

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(lineno)d %(module)s %(message)s')

logger=logging.getLogger(__name__)


from init import *

def float_equal(f1, f2):
    return abs(f1 - f2) <= 1e-9

def compile_contract(contract_source_code, main_class):
    compiled_sol = compile_source(contract_source_code) # Compiled source code
    contract_interface = compiled_sol[main_class]
    return contract_interface


main_account = 'helloworld11'
test_account = 'helloworld12'
eth = Eth(main_account)

def load_contract(file_name, main_class):
    src = open(file_name, 'r').read()
    contract_interface = compile_contract(src, f'<stdin>:{main_class}')
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']
    return w3.eth.contract(abi=abi, bytecode=bytecode)

Greeter = load_contract('sol/greeter.sol', 'Greeter')
Tester = load_contract('sol/tester.sol', 'Tester')
Callee = load_contract('sol/callee.sol', 'Callee')

class ShareValues(object):
    eth_address = None
    main_eth_address = None
    contract_address = None
    callee_contract_address = None
    tester_contract_address = None

shared = ShareValues()

class BaseTestCase(unittest.TestCase):
    initialized = False

    def __init__(self, testName, extra_args=[]):
        super(BaseTestCase, self).__init__(testName)
        self.init_testcase()

    @classmethod
    def init_testcase(cls):
        logger.info(f'{bcolors.OKGREEN}++++++++++BaseTestCase.init_testcase++++++++++++++{bcolors.ENDC}')
        # cls = type(self)
        if shared.eth_address:
            return
        try:
            vm_abi = open('./contracts/ethereum_vm/ethereum_vm.abi', 'rb').read()
            vm_code = open('./contracts/ethereum_vm/ethereum_vm.wasm', 'rb').read()
            r = eosapi.publish_contract('helloworld11', vm_code, vm_abi, vmtype=0, vmversion=0, sign=True, compress=1)
            print(r['processed']['elapsed'])
        except Exception as e:
            print(e)

        try:
            context_file = './gen_context.bin'
            context = open(context_file, 'rb').read()
            r = eosapi.push_action(main_account, 'init', context, {main_account:'active'})
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

        args = {'chainid': 1}
        try:
            r = eosapi.push_action(main_account, 'setchainid', args, {main_account:'active'})
            print('++++console:', r['processed']['action_traces'][0]['console'])
            print(r['processed']['elapsed'])
        except Exception as e:
            print(e)

        shared.eth_address = eth.get_binded_address(test_account)
        if not shared.eth_address:
            args = {'account': test_account, 'text': 'hello,world'}
            try:
                r = eosapi.push_action(main_account, 'create', args, {test_account:'active'})
                shared.eth_address = r['processed']['action_traces'][0]['console']
                print('eth address:', shared.eth_address)
                print(r['processed']['elapsed'])
            except Exception as e:
                if hasattr(e, 'response'):
                    parsed = json.loads(e.response)
                    print('+++error:\n', json.dumps(parsed, indent=4))
                else:
                    print(e)
                sys.exit(-1)
            assert shared.eth_address == eth.get_binded_address(test_account)

            assert eth.get_balance(shared.eth_address) == 0.0
            assert eth.get_nonce(shared.eth_address) == 1

        #verify eth address
        e = rlp.encode([test_account, 'hello,world'])
        h = keccak(e)
        print(h[12:].hex(), shared.eth_address)
        assert h[12:].hex() == shared.eth_address
        shared.contract_address = None

        shared.main_eth_address = eth.get_binded_address(main_account)
        if not shared.main_eth_address:
            args = {'account': main_account, 'text': 'hello,world'}
            try:
                r = eosapi.push_action(main_account, 'create', args, {main_account:'active'})
                shared.main_eth_address = r['processed']['action_traces'][0]['console']
                print('eth address:', shared.main_eth_address)
                print(r['processed']['elapsed'])
            except Exception as e:
                if hasattr(e, 'response'):
                    parsed = json.loads(e.response)
                    print('+++error:\n', json.dumps(parsed, indent=4))
                else:
                    print(e)
                sys.exit(-1)
            assert shared.main_eth_address == eth.get_binded_address(main_account)

            assert eth.get_balance(shared.main_eth_address) == 0.0
            assert eth.get_nonce(shared.main_eth_address) == 1
        eosapi.transfer(test_account, main_account, 10.0, 'deposit')
        BaseTestCase.initialized = True

    @classmethod
    def tearDownClass(cls):
        pass

class EVMTestCase(BaseTestCase):
    def __init__(self, testName, extra_args=[]):
        super(EVMTestCase, self).__init__(testName)
        self.extra_args = extra_args
        
        evm.set_current_account(test_account)
        evm.set_chain_id(1)
        self.deploy_evm_contract()

    @classmethod
    def setUpClass(cls):
        BaseTestCase.setUpClass()

    def deposit(self, account, amount):
        evm.set_current_account(test_account)
        r = eosapi.transfer(account, main_account, amount, 'deposit')

    def test_deposit(self):
        # Deposit Test
        evm.set_current_account(test_account)
        balance = eth.get_balance(shared.eth_address)
        logger.info(('++++balance:', balance, eosapi.config.main_token))
        r = eosapi.transfer(test_account, main_account, 10.1, 'deposit')
        assert eth.get_balance(shared.eth_address) == balance + 10.1

    def test_withdraw(self):
        ### Withdraw test
        evm.set_current_account(test_account)
        args = {'account': test_account, 'amount': '1.0000 SYS'}
        try:
            eos_balance = eosapi.get_balance(test_account)
            eth_balance = eth.get_balance(shared.eth_address)
            
            r = eosapi.push_action(main_account, 'withdraw', args, {test_account:'active'})
            print('++++console:', r['processed']['action_traces'][0]['console'])
            print(r['processed']['elapsed'])

            assert eth_balance - 1.0 == eth.get_balance(shared.eth_address)
            assert eos_balance + 1.0 == eosapi.get_balance(test_account)
        except Exception as e:
            print(e)

    def test_overdraw(self):
        #Overdraw test
        evm.set_current_account(test_account)

        eth_balance = eth.get_balance(shared.eth_address)
        logger.info(('++++eth_balance:', eth_balance))
        args = {'account': test_account, 'amount': '%.4f SYS'%(eth_balance+0.1,)}
        logger.info(('++++args:', args))
        try:
            r = eosapi.push_action(main_account, 'withdraw', args, {test_account:'active'})
            print('++++console:', r['processed']['action_traces'][0]['console'])
            #should not go here
            assert 0
        except Exception as e:
            assert eth_balance == eth.get_balance(shared.eth_address)
            e = json.loads(e.response)
            assert e['error']['details'][0]['message'] == "assertion failure with message: balance overdraw!"

    def deploy_evm_contract(self):
        logger.info((self, shared.contract_address))
        if shared.contract_address:
            return
        evm.set_current_account(test_account)

        nonce = eth.get_nonce(shared.eth_address)
        e = rlp.encode([bytes.fromhex(shared.eth_address), nonce])
        h = keccak(e)
        expected_address = h[12:].hex()

        #test deploy evm contract
        logs = Greeter.constructor().transact({'from': shared.eth_address})
        shared.contract_address = logs[0].hex()

        logger.info((expected_address, shared.contract_address))

        assert expected_address == shared.contract_address
        assert eth.get_nonce(shared.eth_address) == nonce + 1

        #test get contract code
        code = eth.get_code(shared.contract_address)
        # logger.info(code)
        # logger.info( logs[1].hex())

        assert code
        #  == logs[1].hex()

    def test_set_value(self):
        evm.set_current_account(test_account)

        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        #test storage
        args = {'from': shared.eth_address,'to': checksum_contract_address}

        logs = Greeter.functions.setValue(0xaabbccddee).transact(args)
        evm.format_log(logs)
        print(logs)

        values = eth.get_all_values(shared.contract_address)
        logger.info(values)
        # contract_address = w3.toChecksumAddress(output['new_address'])
        # print('+++contract_address:', contract_address)

    def test_authorization(self):
        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        logger.info(f'{bcolors.OKGREEN}++++++++++test call evm contract with wrong authorization{bcolors.ENDC}')
        try:
            evm.set_current_account(main_account)
            args = {'from': shared.eth_address,'to': checksum_contract_address}
            ret = Greeter.functions.setValue(0xaabbccddee).transact(args)
            assert 0
        except Exception as e:
            e = json.loads(e.response)
            assert e['error']['details'][0]['message'] == 'missing authority of helloworld12'

    def transfer_eth(self, _from, _to, _value):
        evm.set_current_account('helloworld12')
        args = {'from': w3.toChecksumAddress(_from),'to': w3.toChecksumAddress(_to), 'value':_value}
        ret = Greeter.functions.transfer().transact(args)

    def test_transfer_eth(self):
        evm.set_current_account('helloworld12')
        eosapi.transfer('helloworld12', 'helloworld11', 1.0)
        balance1 = eth.get_balance(shared.eth_address)
        balance2 = eth.get_balance(shared.main_eth_address)

        transaction = {
                'from':shared.eth_address,
                'to': w3.toChecksumAddress(shared.main_eth_address),
                'value': 1000,
                'gas': 2000000,
                'gasPrice': 234567897654321,
                'nonce': 0,
                'chainId': 1
        }
        w3.eth.sendTransaction(transaction)

        logger.info((balance1, eth.get_balance(shared.eth_address)))

        assert float_equal(balance1, eth.get_balance(shared.eth_address)+0.1)
        assert float_equal(balance2+0.1, eth.get_balance(shared.main_eth_address))

    def test_transfer_eth_to_not_created_address(self):
        evm.set_current_account('helloworld12')
        eosapi.transfer('helloworld12', 'helloworld11', 1.0, 'hello')
        transaction = {
                'from':shared.eth_address,
                'to': '0xF0109fC8DF283027b6285cc889F5aA624EaC1F55',
                'value': 1000,
                'gas': 2000000,
                'gasPrice': 0,
                'nonce': 0,
                'chainId': 1
        }
        try:
            w3.eth.sendTransaction(transaction)
        except Exception as e:
            e = json.loads(e.response)
            assert e['error']['details'][0]['message'] == "assertion failure with message: get_balance:address does not created!"

    def test_transfer_back(self):
        self.deploy_evm_contract()
        evm.set_current_account(test_account)

        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        
        self.deposit(test_account, 1.0)

        logger.info((shared.eth_address, "balance", eth.get_balance(shared.eth_address)))
        self.transfer_eth(shared.eth_address, shared.contract_address, 1000)

        balance1 = eth.get_balance(shared.eth_address)
        balance2 = eth.get_balance(shared.contract_address)

        args = {'from': shared.eth_address,'to': checksum_contract_address}
        logs = Greeter.functions.transferBack(1000).transact(args)

        float_equal(balance1+0.1, eth.get_balance(shared.eth_address))
        float_equal(balance2-0.1, eth.get_balance(shared.contract_address))
        evm.format_log(logs)
        print(logs)

    def test_block_info(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}
        logs = Greeter.functions.testBlockInfo().transact(args)

    def test_ecrecover(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}

        from eth_keys import keys
        from eth_utils import keccak, to_bytes
        h = keccak(b'a message')
        pk = keys.PrivateKey(b'\x01' * 32)
        sign = pk.sign_msg_hash(h)
        print(h, sign.v, sign.r, sign.s)
        r = to_bytes(sign.r)
        s = to_bytes(sign.s)
        logs = Greeter.functions.ecrecoverTest(h, sign.v+27, r, s).transact(args)
        logger.info(logs)
        pub_key = sign.recover_public_key_from_msg(b'a message')
        address = pub_key.to_canonical_address()
        logger.info(pub_key)
        logger.info(address)
        assert logs[1][12:] == address

    def test_ripemd160(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}

        logs = Greeter.functions.ripemd160Test(b'a message').transact(args)
        logger.info(logs)

        import hashlib
        h = hashlib.new('ripemd160')
        h.update(b'a message')
        digest = h.digest()
        logger.info((digest))
        assert logs[1][:20] == digest

    def test_sha256(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}

        logs = Greeter.functions.sha256Test(b'another message').transact(args)
        logger.info(logs)

        import hashlib
        h = hashlib.sha256()
        h.update(b'another message')
        digest = h.digest()
        logger.info((digest))
        assert logs[1] == digest

    def setUp(self):
        pass

    def tearDown(self):
        pass

class EVMTestCase2(BaseTestCase):
    
    tester_contract_address = None

    def __init__(self, testName, extra_args=[]):
        super().__init__(testName)
        self.extra_args = extra_args
        
        evm.set_current_account(test_account)
        evm.set_chain_id(1)
        self.init_testcase2()

    def init_testcase2(self):
        if shared.callee_contract_address:
            return

        logs = Tester.constructor().transact({'from': shared.eth_address})
        shared.tester_contract_address = logs[0].hex()
        logger.info(shared.tester_contract_address)

        logs = Callee.constructor().transact({'from': shared.eth_address})
        shared.callee_contract_address = logs[0].hex()
        logger.info(shared.callee_contract_address)

    @classmethod
    def setUpClass(cls):
        super(EVMTestCase2, cls).setUpClass()

    def test_call_other_contract(self):
        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.tester_contract_address)
        callee_address = w3.toChecksumAddress(shared.callee_contract_address)
        args = {'from': _from, 'to': _to}

        value = 2
        logs = Tester.functions.testCall(callee_address, value).transact(args)
        ret_value = int.from_bytes(logs[1], 'big')
        assert ret_value == value + 1

    def test_suicide(self):
        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.tester_contract_address)
        args = {'from': _from, 'to': _to, 'value': 10000}
        logs = Tester.functions.transfer().transact(args)
        logger.info(logs)
        balance11 = eth.get_balance(shared.eth_address)
        balance21 = eth.get_balance(shared.tester_contract_address)
        logger.info((balance11, balance21))
        args = {'from': _from, 'to': _to}
        logs = Tester.functions.testSuicide().transact(args)

        balance12 = eth.get_balance(shared.eth_address)
        balance22 = eth.get_balance(shared.tester_contract_address)
        logger.info((balance12, balance22))

        assert balance22 == 0
        assert balance12 == balance11 + balance21
        assert not eth.get_code(shared.tester_contract_address)


def suite():
    suite = unittest.TestSuite()

    suite.addTest(EVMTestCase('test_deposit'))
    suite.addTest(EVMTestCase('test_withdraw'))
    suite.addTest(EVMTestCase('test_overdraw'))
    suite.addTest(EVMTestCase('test_set_value'))
    suite.addTest(EVMTestCase('test_authorization'))
    suite.addTest(EVMTestCase('test_transfer_eth'))
    suite.addTest(EVMTestCase('test_transfer_eth_to_not_created_address'))
    suite.addTest(EVMTestCase('test_transfer_back'))

    suite.addTest(EVMTestCase2('test_call_other_contract'))

    return suite

if __name__ == '__main__':
    # runner = unittest.TextTestRunner(failfast=True)
    # runner.run(suite())
    unittest.main()

print('Done!')

