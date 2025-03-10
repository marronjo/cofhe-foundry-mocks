// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {ExampleFHECounter} from "./ExampleFHECounter.sol";
import {CoFheTest} from "../src/CoFheTest.sol";
import {FHE, euint32, inEuint32} from "../src/FHE.sol";
import {Permission} from "../src/Permissioned.sol";

contract QueryDecryptExample {
    mapping(address => euint32) private balances;

    function getBalance(address account) public view returns (euint32) {
        return balances[account];
    }

    function setBalance(inEuint32 memory inAmount) public {
        balances[msg.sender] = FHE.asEuint32(inAmount);
        FHE.allow(balances[msg.sender], msg.sender);
    }
}

contract QueryDecryptTest is Test {
    CoFheTest CFT;

    QueryDecryptExample public example;

    uint256 bobPKey;
    address bob;

    uint256 alicePKey;
    address alice;

    function setUp() public {
        CFT = new CoFheTest(false);

        example = new QueryDecryptExample();

        bobPKey = 0xB0B;
        bob = vm.addr(bobPKey);

        alicePKey = 0xA11CE;
        alice = vm.addr(alicePKey);
    }

    function test_getBalance_queryDecrypt_self() public {
        inEuint32 memory inAmount = CFT.createInEuint32(100);

        vm.prank(bob);
        example.setBalance(inAmount);

        euint32 result = example.getBalance(bob);

        Permission memory permission = CFT.createPermissionSelf(bob);
        permission = CFT.signPermissionSelf(bobPKey, permission);

        uint256 decrypted = CFT.queryDecrypt(
            permission,
            euint32.unwrap(result)
        );
        assertEq(decrypted, 100);
    }

    function test_getBalance_queryDecrypt_shared() public {
        inEuint32 memory inAmount = CFT.createInEuint32(100);

        vm.prank(bob);
        example.setBalance(inAmount);

        euint32 result = example.getBalance(bob);

        Permission memory permission = CFT.createPermissionShared(bob, alice);
        permission = CFT.signPermissionShared(bobPKey, permission);
        permission = CFT.signPermissionRecipient(alicePKey, permission);

        uint256 decrypted = CFT.queryDecrypt(
            permission,
            euint32.unwrap(result)
        );
        assertEq(decrypted, 100);
    }
}
