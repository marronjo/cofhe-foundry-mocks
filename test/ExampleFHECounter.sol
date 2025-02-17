// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {FHE, euint32, inEuint32, IAsyncFHEReceiver} from "../src/FHE.sol";

contract ExampleFHECounter is IAsyncFHEReceiver {
    euint32 public eNumber;
    mapping(uint256 ctHash => uint256) public decryptedRes;
    mapping(uint256 ctHash => string) public sealedRes;

    function setNumber(inEuint32 memory inNumber) public {
        eNumber = FHE.asEuint32(inNumber);
        FHE.allowThis(eNumber);
    }

    function increment() public {
        eNumber = FHE.add(eNumber, FHE.asEuint32(1));
        FHE.allowThis(eNumber);
    }

    function add(inEuint32 memory inNumber) public {
        eNumber = FHE.add(eNumber, FHE.asEuint32(inNumber));
        FHE.allowThis(eNumber);
    }

    function sub(inEuint32 memory inNumber) public {
        euint32 inAsEuint32 = FHE.asEuint32(inNumber);
        euint32 eSubOrZero = FHE.select(
            FHE.lte(inAsEuint32, eNumber),
            inAsEuint32,
            FHE.asEuint32(0)
        );
        eNumber = FHE.sub(eNumber, eSubOrZero);
        FHE.allowThis(eNumber);
    }

    function mul(inEuint32 memory inNumber) public {
        eNumber = FHE.mul(eNumber, FHE.asEuint32(inNumber));
        FHE.allowThis(eNumber);
    }

    function decrypt() public {
        FHE.decrypt(eNumber);
    }

    function sealoutput(bytes32 publicKey) public {
        FHE.sealoutput(eNumber, publicKey);
    }

    function handleDecryptResult(
        uint256 ctHash,
        uint256 result,
        address
    ) external override {
        decryptedRes[ctHash] = result;
    }

    function handleSealOutputResult(
        uint256 ctHash,
        string memory result,
        address
    ) external override {
        sealedRes[ctHash] = result;
    }
}
