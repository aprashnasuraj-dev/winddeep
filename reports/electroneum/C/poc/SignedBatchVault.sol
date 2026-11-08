// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Isolated, deliberately simple EIP-712 batch authorizer for a disclosure
// discriminator. This contract is not claimed to be deployed by Electroneum.
// It correctly verifies the COMPLETE signed batch, not the UI's truncated view.
contract SignedBatchVault {
    struct Payment { address payee; uint256 amount; }
    mapping(address => uint256) public funds;
    mapping(address => uint256) public nonces;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant PAYMENT_TYPEHASH =
        keccak256("Payment(address payee,uint256 amount)");
    bytes32 private constant BATCH_TYPEHASH =
        keccak256("Batch(Payment[] instructions,uint256 nonce)Payment(address payee,uint256 amount)");
    bytes32 private constant NAME_HASH = keccak256("Clef Batch Authorization");
    bytes32 private constant VERSION_HASH = keccak256("1");
    event Paid(address indexed owner, address indexed to, uint256 amount);

    function depositFor(address owner) external payable {
        require(owner != address(0) && msg.value > 0, "bad deposit");
        funds[owner] += msg.value;
    }
    function execute(address owner, address[] calldata payees, uint256[] calldata amounts,
                     uint8 v, bytes32 r, bytes32 s) external {
        require(owner != address(0) && payees.length > 0 &&
                payees.length == amounts.length, "bad input");
        bytes32[] memory hashes = new bytes32[](payees.length);
        for (uint256 i = 0; i < payees.length; i++) {
            hashes[i] = keccak256(abi.encode(PAYMENT_TYPEHASH, payees[i], amounts[i]));
        }
        bytes32 structHash = keccak256(abi.encode(
            BATCH_TYPEHASH, keccak256(abi.encodePacked(hashes)), nonces[owner]
        ));
        bytes32 domain = keccak256(abi.encode(
            DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)
        ));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domain, structHash));
        require(ecrecover(digest, v, r, s) == owner, "signature mismatch");
        nonces[owner] += 1;
        for (uint256 i = 0; i < payees.length; i++) {
            require(funds[owner] >= amounts[i], "insufficient deposited funds");
            funds[owner] -= amounts[i];
            (bool ok,) = payable(payees[i]).call{value: amounts[i]}("");
            require(ok, "payment failed");
            emit Paid(owner, payees[i], amounts[i]);
        }
    }
}