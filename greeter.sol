pragma solidity ^0.6.0;
contract Greeter {
    uint value;
    event onSetValue(uint value);
    event onGetValue(uint value);
    constructor() public {
        value = 1;
    }

    function getValue2() payable public returns (uint){
//        msg.sender.transfer(1000);
        emit onGetValue(value);
        return value;
    }

    function getValue() payable public returns (string memory){
        return "hello,world";
    }

    function setValue(uint v) payable public {
        value = v;
        emit onSetValue(v);
    }
}
