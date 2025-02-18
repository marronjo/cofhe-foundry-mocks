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
        CFT = new CoFheTest(false);

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

        uint8 count = 0;
        bool success = false;
        while (!success && count < 100) {
            try counter.getDecryptResult(counter.eNumber()) returns (uint32) {
                success = true;
            } catch {
                vm.warp(block.timestamp + 1);
                count += 1;
            }
        }
    }

    function test_decryptSafe() public {
        CFT.assertStoredValue(counter.eNumber(), 5);
        counter.decrypt();

        uint8 count = 0;
        bool success = false;
        while (!success && count < 100) {
            (uint256 result, bool decrypted) = counter.getDecryptResultSafe(
                counter.eNumber()
            );
            if (decrypted) {
                assertEq(result, 5);
                success = true;
            } else {
                vm.warp(block.timestamp + 1);
                count += 1;
            }
        }
    }
}
