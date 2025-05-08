// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {CoFheTest} from "../src/CoFheTest.sol";
import {EncryptedInput} from "@fhenixprotocol/cofhe-contracts/ICofhe.sol";
import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract MockZkVerifierTests is Test {
    CoFheTest CFT;

    function setUp() public {
        CFT = new CoFheTest(false);
    }

    function test_zkVerify() public {
        address sender = address(128);

        EncryptedInput memory input = CFT.zkVerifier().zkVerify(
            5,
            Utils.EUINT8_TFHE,
            sender,
            0,
            block.chainid
        );

        input = CFT.zkVerifierSigner().zkVerifySign(input, sender);

        // Hash should be in storage
        CFT.assertHashValue(input.ctHash, 5);

        // Signature should be valid
        CFT.taskManager().verifyInput(input, sender);
    }

    function test_zkVerifyPacked() public {
        uint8[] memory utypes = new uint8[](2);
        utypes[0] = Utils.EUINT8_TFHE;
        utypes[1] = Utils.EUINT8_TFHE;

        uint256[] memory values = new uint256[](2);
        values[0] = 5;
        values[1] = 6;

        address sender = address(128);

        EncryptedInput[] memory inputs = CFT.zkVerifier().zkVerifyPacked(
            values,
            utypes,
            sender,
            0,
            block.chainid
        );

        inputs = CFT.zkVerifierSigner().zkVerifySignPacked(inputs, sender);

        // Hash should be in storage
        CFT.assertHashValue(inputs[0].ctHash, 5);
        CFT.assertHashValue(inputs[1].ctHash, 6);

        CFT.taskManager().verifyInput(inputs[0], sender);
        CFT.taskManager().verifyInput(inputs[1], sender);
    }

    function test_zkVerifier_as_mock() public {
        address sender = address(128);

        uint8[] memory utypes = new uint8[](2);
        utypes[0] = Utils.EUINT8_TFHE;
        utypes[1] = Utils.EUINT8_TFHE;

        uint256[] memory values = new uint256[](2);
        values[0] = 5;
        values[1] = 6;

        uint256[] memory ctHashes = CFT.zkVerifier().zkVerifyCalcCtHashesPacked(
            values,
            utypes,
            sender,
            0,
            block.chainid
        );

        CFT.zkVerifier().insertPackedCtHashes(ctHashes, values);

        // Hash should be in storage
        CFT.assertHashValue(ctHashes[0], 5);
        CFT.assertHashValue(ctHashes[1], 6);
    }
}
