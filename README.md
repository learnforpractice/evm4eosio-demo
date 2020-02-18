# Get Started

## Clone Demo From Github
```
git clone https://github.com/learnforpractice/eos-with-evm-demo
cd eos-with-evm-demo
```

## Setup Python Environment

```
python3.7 -m pip install virtualenv
python3.7 -m virtualenv .venv
. .venv/bin/activate
```

### Install PyEosKit

#### Ubuntu

```
python3.7 -m pip https://github.com/learnforpractice/pyeoskit/releases/download/v0.7.0/pyeoskit-0.7.0-cp37-cp37m-linux_x86_64.whl
```

#### Mac OS X
```
python3.7 -m pip https://github.com/learnforpractice/pyeoskit/releases/download/v0.7.0/pyeoskit-0.7.0-cp37-cp37m-macosx_10_9_x86_64.whl
```

### Install Jupyter Notebook
```
python3.7 -m pip install notebook
```

### Install Solc Compiler
```
python3.7 -m pip install py-solc-x
```

### Install Web3

```
python3.7 -m pip install --pre web3[tester]==5.5.0
```

## Start a Testnet
```
nodeos  --verbose-http-errors  --http-max-response-time-ms 100 --data-dir dd --config-dir cd --wasm-runtime eos-vm-jit --contracts-console -p eosio -e --plugin eosio::producer_plugin --plugin eosio::chain_api_plugin --plugin eosio::producer_api_plugin
```

## Initialize the Testnet
At the same directory, run the following command:
```
python3.7 testnet-init.py
```

## Open Jupyter Notebook
In eos-with-evm-demo directory, run the following command
```
python3.7 -m notebook
```

Open hello_evm.ipynb and run code in cell one by one

## Run TestCase

```
python3.7 evm_test.py
```
