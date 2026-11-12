// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.0;

import "openzeppelin-solidity/contracts/cryptography/ECDSA.sol";

contract SwapContractAggregateSignature {

    struct Swap {
        uint refundTimeInBlocks;
        address initiator;
        address participant;
        uint256 value;
    }

    mapping(address => Swap) swaps;

    function initiate(uint refundTimeInBlocks, address addressFromSecret, address participant) public
        payable
    {
        require(swaps[addressFromSecret].refundTimeInBlocks == 0, "swap for this hash is already initiated");
        require(participant != address(0), "invalid participant address");
        require(block.number < refundTimeInBlocks, "refundTimeInBlocks has already come");

        swaps[addressFromSecret].refundTimeInBlocks = refundTimeInBlocks;
        swaps[addressFromSecret].participant = participant;
        swaps[addressFromSecret].initiator = msg.sender;
        swaps[addressFromSecret].value = msg.value;
    }

    function redeem(address addressFromSecret, bytes32 r, bytes32 s, uint8 v) public
    {
        require(msg.sender == swaps[addressFromSecret].participant, "invalid msg.sender");

        bytes32 hash = keccak256(abi.encodePacked(addressFromSecret, swaps[addressFromSecret].participant, swaps[addressFromSecret].initiator, swaps[addressFromSecret].refundTimeInBlocks));

        // If the signature is valid (and not malleable), return the signer address
        bytes32 ethSignedMessageHash = ECDSA.toEthSignedMessageHash(hash);
        address signer = ECDSA.recover(ethSignedMessageHash,  abi.encodePacked(r, s, v));

        require(signer == addressFromSecret, "invalid address");

        Swap memory tmp = swaps[addressFromSecret];
        delete swaps[addressFromSecret];

        (bool success, ) = payable(tmp.participant).call{value: tmp.value}("");
        require(success, "Transfer failed.");
    }

    function refund(address addressFromSecret) public
    {
        require(block.number >= swaps[addressFromSecret].refundTimeInBlocks, "refundTimeInBlocks has not come");
        require(msg.sender == swaps[addressFromSecret].initiator, "invalid msg.sender");

        Swap memory tmp = swaps[addressFromSecret];
        delete swaps[addressFromSecret];

        (bool success, ) = payable(tmp.initiator).call{value: tmp.value}("");
        require(success, "Transfer failed.");
    }

    function getSwapDetails(address addressFromSecret)
    public view returns (uint refundTimeInBlocks, address initiator, address participant, uint256 value)
    {
        refundTimeInBlocks = swaps[addressFromSecret].refundTimeInBlocks;
        initiator = swaps[addressFromSecret].initiator;
        participant = swaps[addressFromSecret].participant;
        value = swaps[addressFromSecret].value;
    }
}