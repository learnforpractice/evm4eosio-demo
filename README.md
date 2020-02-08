## Compile eos-with-evm source

Refer to https://github.com/learnforpractice/eos-with-evm for a build instruction and run a testnet

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
python3.7 -m pip install --pre web3[tester]
```

## Initialize the Testnet
cd to directory tests of eos-wit-evm source code, run:
```
python3.7 testnet-init.py
```

### Open Jupyter Notebook
In eos-with-evm-demo directory, run the following command
```
python3.7 -m notebook
```

Open hello_evm.ipynb and run code in cell one by one
