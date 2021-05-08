/// ETH Swap contract abi
pub const ETH_SWAP_CONTRACT: &str = r#"[
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "refundTimeInBlocks",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "addressFromSecret",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "participant",
          "type": "address"
        }
      ],
      "name": "initiate",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function",
      "payable": true
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "addressFromSecret",
          "type": "address"
        },
        {
          "internalType": "bytes32",
          "name": "r",
          "type": "bytes32"
        },
        {
          "internalType": "bytes32",
          "name": "s",
          "type": "bytes32"
        },
        {
          "internalType": "uint8",
          "name": "v",
          "type": "uint8"
        }
      ],
      "name": "redeem",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "addressFromSecret",
          "type": "address"
        }
      ],
      "name": "refund",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "addressFromSecret",
          "type": "address"
        }
      ],
      "name": "getSwapDetails",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "refundTimeInBlocks",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "initiator",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "participant",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "value",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    }
  ]"#;
