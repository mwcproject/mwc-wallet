// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.0;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/utils/Address.sol";
import "openzeppelin-solidity/contracts/token/ERC20/SafeERC20.sol";
import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";
import "openzeppelin-solidity/contracts/cryptography/ECDSA.sol";

contract ERC20SwapContractAggregateSignature {
    using SafeERC20 for IERC20;

    struct Swap {
        uint refundTimeInBlocks;
        address contractAddress;
        address initiator;
        address participant;
        uint256 value;
    }

    mapping(address => Swap) swaps;

    function initiate(uint refundTimeInBlocks, address addressFromSecret, address participant, address contractAddress, uint256 value) public
    {
        require(swaps[addressFromSecret].refundTimeInBlocks == 0, "swap for this hash is already initiated");
        require(participant != address(0), "invalid participant address");
        require(block.number < refundTimeInBlocks, "refundTimeInBlocks has already come");

        swaps[addressFromSecret].refundTimeInBlocks = refundTimeInBlocks;
        swaps[addressFromSecret].contractAddress = contractAddress;
        swaps[addressFromSecret].participant = participant;
        swaps[addressFromSecret].initiator = msg.sender;
        swaps[addressFromSecret].value = value;

        IERC20(contractAddress).safeTransferFrom(msg.sender, address(this), value);
    }

    function redeem(address addressFromSecret, bytes32 r, bytes32 s, uint8 v) public
    {
        require(msg.sender == swaps[addressFromSecret].participant, "invalid msg.sender");

        bytes32 hash = keccak256(abi.encodePacked(addressFromSecret, swaps[addressFromSecret].participant, swaps[addressFromSecret].initiator, swaps[addressFromSecret].refundTimeInBlocks, swaps[addressFromSecret].contractAddress));

        // If the signature is valid (and not malleable), return the signer address
        bytes32 ethSignedMessageHash = ECDSA.toEthSignedMessageHash(hash);
        address signer = ECDSA.recover(ethSignedMessageHash,  abi.encodePacked(r, s, v));

        require(signer == addressFromSecret, "invalid address");

        Swap memory tmp = swaps[addressFromSecret];
        delete swaps[addressFromSecret];

        IERC20(tmp.contractAddress).safeTransfer(tmp.participant, tmp.value);
    }

    function refund(address addressFromSecret) public
    {
        require(block.number >= swaps[addressFromSecret].refundTimeInBlocks, "refundTimeInBlocks has not come");
        require(msg.sender == swaps[addressFromSecret].initiator, "invalid msg.sender");

        Swap memory tmp = swaps[addressFromSecret];
        delete swaps[addressFromSecret];

        IERC20(tmp.contractAddress).safeTransfer(tmp.initiator, tmp.value);
    }

    function getSwapDetails(address addressFromSecret)
    public view returns (uint refundTimeInBlocks, address contractAddress, address initiator, address participant, uint256 value)
    {
        refundTimeInBlocks = swaps[addressFromSecret].refundTimeInBlocks;
        contractAddress = swaps[addressFromSecret].contractAddress;
        initiator = swaps[addressFromSecret].initiator;
        participant = swaps[addressFromSecret].participant;
        value = swaps[addressFromSecret].value;
    }
}