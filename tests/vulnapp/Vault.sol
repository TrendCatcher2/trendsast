pragma solidity ^0.8.0;
contract Vault {
  address owner;
  function withdraw() public { require(tx.origin == owner, "no"); payable(msg.sender).send(1); }
  function exec(address target, bytes memory data) public { target.delegatecall(data); }
  function pull(address from, uint amt) external { token.transferFrom(from, address(this), amt); }
  function initialize(address o) public { owner = o; }
  function rnd() public view returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))); }
}
