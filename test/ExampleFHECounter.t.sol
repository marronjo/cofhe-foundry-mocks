// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ExampleFHECounter} from "./ExampleFHECounter.sol";
import {CoFheTest} from "../src/CoFheTest.sol";
import {FHE, euint32, inEuint32} from "../src/FHE.sol";
contract ExampleFHECounterTest is Test {
    CoFheTest CFT;

    ExampleFHECounter public counter;

    function setUp() public {
        CFT = new CoFheTest();

        counter = new ExampleFHECounter();

        // Set number to 5
        inEuint32 memory inNumber = CFT.createInEuint32(5);
        counter.setNumber(inNumber);
    }

    function test_setNumber() public {
        inEuint32 memory inNumber = CFT.createInEuint32(10);
        counter.setNumber(inNumber);
        CFT.assertStoredValue(counter.eNumber(), 10);
    }

    function test_increment() public {
        counter.increment();
        CFT.assertStoredValue(counter.eNumber(), 6);
    }

    function test_add() public {
        inEuint32 memory inNumber = CFT.createInEuint32(2);
        counter.add(inNumber);
        CFT.assertStoredValue(counter.eNumber(), 7);
    }

    function test_sub() public {
        inEuint32 memory inNumber = CFT.createInEuint32(3);
        counter.sub(inNumber);
        CFT.assertStoredValue(counter.eNumber(), 2);
    }

    function test_mul() public {
        inEuint32 memory inNumber = CFT.createInEuint32(2);
        counter.mul(inNumber);
        CFT.assertStoredValue(counter.eNumber(), 10);
    }

    function test_decrypt() public {
        CFT.assertStoredValue(counter.eNumber(), 5);
        counter.decrypt();
        assertEq(counter.decryptedRes(euint32.unwrap(counter.eNumber())), 5);
    }

    function test_sealoutput() public {
        CFT.assertStoredValue(counter.eNumber(), 5);

        bytes32 publicKey = bytes32("0xFakePublicKey");

        counter.sealoutput(publicKey);

        uint256 unsealed = CFT.unseal(
            counter.sealedRes(euint32.unwrap(counter.eNumber())),
            publicKey
        );

        assertEq(unsealed, 5);
    }
}
