import sys
import json
import time
import rlp
import hashlib
import logging
import unittest
import evm
from evm import Eth, EthAccount
from evm import w3, hex2int
import base58

from eth_utils import keccak
from solcx import compile_source, compile_files
from init import *

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

def on_test(func):
    def decorator(self, *args, **kwargs):
        logger.info(f'{bcolors.OKGREEN}++++++++++{type(self).__name__}.{func.__name__}++++++++++++++{bcolors.ENDC}')
        return func(self, *args, **kwargs)
    return decorator

# "env" : {
#     "currentCoinbase" : "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
#     "currentDifficulty" : "0x0100",
#     "currentGasLimit" : "0x0f4240",
#     "currentNumber" : "0x00",
#     "currentTimestamp" : "0x01"
# },
# "exec" : {
#     "address" : "0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6",
#     "caller" : "0xcd1722f3947def4cf144679da39c4c32bdc35681",
#     "code" : "0x6000600020600055",
#     "data" : "0x",
#     "gas" : "0x174876e800",
#     "gasPrice" : "0x3b9aca00",
#     "origin" : "0xcd1722f3947def4cf144679da39c4c32bdc35681",
#     "value" : "0x0de0b6b3a7640000"
# },
# "gas" : "0x17487699b9",
# "logs" : "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
# "out" : "0x",
# "post" : {
#     "0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6" : {
#         "balance" : "0x152d02c7e14af6800000",
#         "code" : "0x6000600020600055",
#         "nonce" : "0x00",
#         "storage" : {
#             "0x00" : "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
#         }
#     }
# },
# "pre" : {
#     "0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6" : {
#         "balance" : "0x152d02c7e14af6800000",
#         "code" : "0x6000600020600055",
#         "nonce" : "0x00",
#         "storage" : {
#         }
#     }
# }


def convert_post_storage(s):
    _s = {}
    for key in s:
        value = s[key]
        value = hex2int(value)
        key = hex2int(key)
        _s[key] = value
    return _s

def convert_storage(s):
    out = {}
    for _s in s:
        key = hex2int(_s['key'])
        value = hex2int(_s['value'])
        out[key] = value
    return out

def run_test(json_file):
    with open(json_file, 'r') as f:
        tests = f.read()
    tests = json.loads(tests)

    r = eosapi.push_action('helloworld11', 'clearenv', json_file.encode('utf8'), {'helloworld11': 'active'})

    for name in tests:
        print(name)
        test = tests[name]
        logger.info(test['pre'])
        for addr in test['pre']:
            logger.info(addr)
            info = test['pre'][addr]
            balance = evm.hex2int(info['balance'])
            balance = int.to_bytes(balance, 32, 'little')
            balance = balance.hex()
            code = info['code'][2:]
            nonce = evm.hex2int(info['nonce'])
            args = dict(address=addr[2:], nonce=nonce, balance=balance, code=code)
            logger.info(args)
            logger.info("hello,world")
            r = eosapi.push_action('helloworld11', 'setaddrinfo', args, {'helloworld11': 'active'})
            logger.info("hello,world")
            logger.info(eth.get_all_address_info())
#            {'balance': '0x152d02c7e14af6800000', 'code': '0x6000600020600055', 'nonce': '0x00', 'storage': {}
        trx = test['exec']
        to = trx['address'][2:]
        caller = trx['caller'][2:]

        try:
            #1000000000000000000
            args = dict(address=caller, nonce=1, balance='000064a7b3b6e00d0000000000000000', code='')
            r = eosapi.push_action('helloworld11', 'setaddrinfo', args, {'helloworld11': 'active'})
            logger.info("hello,world")
        except Exception as e:
            print(e)

        # trx['code'][2:]
        # trx['data'][2:]
        # trx['gas'][2:]
        # trx['gasPrice'][2:]
        # trx['origin'][2]
        # trx['value'][2:]
        logger.info((to, eth.get_nonce(to), trx['value'], evm.hex2int(trx['value'])))
        transaction = {
                'nonce': eth.get_nonce(to),
                'gas': evm.hex2int(trx['gas']),
                'gasPrice': evm.hex2int(trx['gasPrice']),
                'from':caller,
                'to': w3.toChecksumAddress(trx['address'][2:]),
                'value': 0, #evm.hex2int(trx['value']),
                'data': trx['data'][2:],
                'chainId': 1
        }

        logs = w3.eth.sendTransaction(transaction)
        logger.info(logs)

        for addr in test['post']:
            post_info = test['post'][addr]
            post_balance = evm.hex2int(post_info['balance'])
            code = post_info['code'][2:]
            nonce = evm.hex2int(post_info['nonce'])
            post_storage = post_info['storage']
            post_storage = convert_post_storage(post_storage)

            balance = eth.get_balance(addr)
            logger.info((post_balance, balance))
            assert balance == post_balance
            assert code == eth.get_code(addr)

            storage = eth.get_all_values(addr)

            storage = convert_storage(storage)
            logger.info(storage)
            for key in post_storage:
                assert key in storage
                assert storage[key] == post_storage[key]

            # "0xcd1722f3947def4cf144679da39c4c32bdc35681" : {
            #     "balance" : "0x152d02c7e14af6800000",
            #     "code" : "0x",
            #     "nonce" : "0x00",
            #     "storage" : {
            #     }
            # }

# "exec" : {
#     "address" : "0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6",
#     "caller" : "0xcd1722f3947def4cf144679da39c4c32bdc35681",
#     "code" : "0x6000600020600055",
#     "data" : "0x",
#     "gas" : "0x174876e800",
#     "gasPrice" : "0x3b9aca00",
#     "origin" : "0xcd1722f3947def4cf144679da39c4c32bdc35681",
#     "value" : "0x0de0b6b3a7640000"
# },


def init_testcase():
    try:
        vm_abi = open('./contracts/ethereum_vm/ethereum_vm.abi', 'rb').read()
        vm_code = open('./contracts/ethereum_vm/ethereum_vm.wasm', 'rb').read()
        r = eosapi.publish_contract('helloworld11', vm_code, vm_abi, vmtype=0, vmversion=0, sign=True, compress=1)
        logger.info(r['processed']['elapsed'])
    except Exception as e:
        print(e)

    import json
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_0.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmTests/suicide.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSystemOperations/return0.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSystemOperations/return2.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSystemOperations/suicide0.json'
    #failure test
    # tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSystemOperations/suicideNotExistingAccount.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSystemOperations/suicideSendEtherToMe.json'

    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_0.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_1.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_2.json'
    #evmc out of gas
    # tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_4.json'
    # tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_5.json'
    # tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_6.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_bigOffset.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test/sha3_memSizeNoQuadraticCost31.json'

    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmRandomTest/201503102320PYTHON.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmRandomTest/201503110206PYTHON.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmRandomTest/201503110219PYTHON.json'
    #log keccak hash mismatch
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmLogTest/log_2logs.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmLogTest/log0_emptyMem.json'

    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/add0.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/add1.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/add2.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/add3.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/add4.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/addmod0.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/addmod1_overflow2.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/addmod1_overflow3.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/addmod1_overflow4.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/addmod1_overflowDiff.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/addmod1.json'
    tests = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest/addmod2_0.json'

    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest'
    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmBitwiseLogicOperation'

    #failed test ['calldatacopyUnderFlow.json', 'gasprice.json', 'callvalue.json']
    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmEnvironmentalInfo'
    #failed test ['loop-mul.json', 'loop-exp-nop-1M.json', 'loop-exp-4b-100k.json', 'loop-divadd-10M.json', 'loop-add-10M.json', 'ackermann33.json', 'loop-mulmod-2M.json', 'loop-exp-1b-1M.json', 'loop-exp-32b-100k.json', 'loop-exp-8b-100k.json', 'loop-exp-16b-100k.json', 'loop-divadd-unr100-10M.json', 'loop-exp-2b-100k.json']
    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmPerformance'
    #['swap2error.json', 'push33.json', 'push32AndSuicide.json', 'dup2error.json']
    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmPushDupSwapTest'
    # ['suicideNotExistingAccount.json']
    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmSystemOperations'
    #['signextend_Overflow_dj42.json':(uninitialized table element) expected?, 'mulUnderFlow.json': throw overflow exception]
    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmArithmeticTest'

    root = '/Users/newworld/dev/ethereum/tests/VMTests/vmSha3Test'

    failed_tests = []
    test_files = os.listdir(root)
    test_files = ['sha3_4.json']
    test_files = ['sha3_2.json']
    # test_files = ['exp6.json', 'mulmod1_overflow.json', 'sdiv3.json', 'mod2.json', 'mulUnderFlow.json', 'sdiv4.json']
    for file in test_files:
        json_file = os.path.join(root, file)
        logger.info(('run test', file))
        import time;
        time.sleep(0.5)
        try:
            run_test(json_file)
        except Exception as e:
            if hasattr(e, 'response'):
                e = json.loads(e.response)
                if file == 'mulUnderFlow.json' and e['error']['details'][0]['message'] == "assertion failure with message: evmc stack underflow":
                    pass
                else:
                    logger.exception(e)
                    failed_tests.append(file)
    logger.info(('failture tests:', failed_tests))
    # json_file = os.path.join(root, 'expPowerOf256Of256_14.json')
    # run_test(json_file)


class EVMTestCase(unittest.TestCase):
    def __init__(self, testName, extra_args=[]):
        super(EVMTestCase, self).__init__(testName)
        self.extra_args = extra_args
        
        evm.set_current_account(test_account)
        evm.set_chain_id(1)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    @on_test
    def test_ecrecover_with_eos_key(self):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

main_account = 'helloworld11'
test_account = 'helloworld12'
eth = Eth(main_account)

#evm.set_eos_public_key('EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV')

if __name__ == '__main__':
    init_testcase()
    unittest.main()

print('Done!')

