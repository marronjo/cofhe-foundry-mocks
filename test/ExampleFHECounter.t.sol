// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ExampleFHECounter} from "./ExampleFHECounter.sol";
import {CoFheTest} from "../src/CoFheTest.sol";
import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract ExampleFHECounterTest is Test {
    CoFheTest CFT;
    address bob = makeAddr("bob");

    ExampleFHECounter public counter;

    function setUp() public {
        CFT = new CoFheTest(false);

        counter = new ExampleFHECounter();

        // Set number to 5
        InEuint32 memory inNumber = CFT.createInEuint32(5, bob);
        vm.prank(bob);
        counter.setNumber(inNumber);
    }

    function test_setNumber() public {
        InEuint32 memory inNumber = CFT.createInEuint32(10, bob);
        counter.setNumber(inNumber);
        CFT.assertHashValue(counter.eNumber(), 10);
    }

    function test_increment() public {
        counter.increment();
        CFT.assertHashValue(counter.eNumber(), 6);
    }

    function test_add() public {
        InEuint32 memory inNumber = CFT.createInEuint32(2, bob);
        counter.add(inNumber);
        CFT.assertHashValue(counter.eNumber(), 7);
    }

    function test_sub() public {
        InEuint32 memory inNumber = CFT.createInEuint32(3, bob);
        counter.sub(inNumber);
        CFT.assertHashValue(counter.eNumber(), 2);
    }

    function test_mul() public {
        InEuint32 memory inNumber = CFT.createInEuint32(2, bob);
        counter.mul(inNumber);
        CFT.assertHashValue(counter.eNumber(), 10);
    }

    function test_decrypt() public {
        CFT.assertHashValue(counter.eNumber(), 5);
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
        CFT.assertHashValue(counter.eNumber(), 5);
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
