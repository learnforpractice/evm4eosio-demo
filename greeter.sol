pragma solidity ^0.6.0;
contract Greeter {
    uint value;
    uint value2;
    uint value3;
    event onSetValue(uint value);
    event onGetValue(uint value);
    event onTransferBack(uint remainBalance);
    event onEmitBytes(bytes bs);
    
    constructor() public {
        value = 1;
        value2 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        value3 = 0x123456789abcdeffffffffffffffffffffffffffffffffffffffffffffffffff;
    }

    // fallback() external payable { }

    // receive() external payable {}

//    function fallback() external payable {}

    function getValue2() payable public returns (uint){
//        msg.sender.transfer(1000);
        emit onGetValue(value);
        return value;
    }

    function getValue() payable public returns (uint){
        return value;
    }

    function setValue(uint v) payable public {
        /*
        require(block.gaslimit == 0x7fffffffffffffff);
        require(block.coinbase == 0x0633A42c777f64f895dE1B0097de00C8D181A5e9);
        require(block.difficulty == 0x020000);
        require(blockhash(0) == 0);
        require(ecrecover(0, 0, 0, 0) == address(0));
        bytes memory a;
        keccak256(a);
        */
//        emit onEmitBytes(abi.encode(1, 2, 3));
        emit onSetValue(v);
        value = v;
    }

    function transfer() payable public {

    }

    function transferBack(uint balance) payable public {
        uint256 oldBalance = msg.sender.balance;
        msg.sender.transfer(balance);
        uint256 newBalance = msg.sender.balance;
        require(oldBalance + balance == newBalance, "bad balance result");
    }
}