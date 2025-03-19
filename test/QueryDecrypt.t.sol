// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {ExampleFHECounter} from "./ExampleFHECounter.sol";
import {CoFheTest} from "../src/CoFheTest.sol";
import "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {PermissionedUpgradeable, Permission, PermissionUtils} from "../src/Permissioned.sol";

interface IIsAllowedWithPermission {
    function isAllowedWithPermission(
        Permission memory permission,
        uint256 handle
    ) external view returns (bool);
}

contract QueryDecryptExample {
    mapping(address => euint32) private balances;

    function getBalance(address account) public view returns (euint32) {
        return balances[account];
    }

    function setBalance(InEuint32 memory inAmount) public {
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

        bobPKey = 0x5a7ebaa3bf002d8b7953167711e527cc352a73414be2af06149b2c39c7edb323;
        bob = vm.addr(bobPKey);

        alicePKey = 0xA11CE;
        alice = vm.addr(alicePKey);
    }

    function test_getBalance_queryDecrypt_self() public {
        InEuint32 memory inAmount = CFT.createInEuint32(100, bob);

        vm.prank(bob);
        example.setBalance(inAmount);

        euint32 result = example.getBalance(bob);

        Permission memory permission = CFT.createPermissionSelf(bob);
        permission = CFT.signPermissionSelf(permission, bobPKey);

        (bool allowed, uint256 decrypted) = CFT.queryDecrypt(
            euint32.unwrap(result),
            block.chainid,
            permission
        );
        assertEq(decrypted, 100);
        assertEq(allowed, true);
    }

    function test_getBalance_queryDecrypt_shared() public {
        InEuint32 memory inAmount = CFT.createInEuint32(100, bob);

        vm.prank(bob);
        example.setBalance(inAmount);

        euint32 result = example.getBalance(bob);

        Permission memory permission = CFT.createPermissionShared(bob, alice);
        permission = CFT.signPermissionShared(permission, bobPKey);
        permission = CFT.signPermissionRecipient(permission, alicePKey);

        (bool allowed, uint256 decrypted) = CFT.queryDecrypt(
            euint32.unwrap(result),
            block.chainid,
            permission
        );
        assertEq(decrypted, 100);
        assertEq(allowed, true);
    }

    function test_getBalance_querySealOutput() public {
        InEuint32 memory inAmount = CFT.createInEuint32(100, bob);

        vm.prank(bob);
        example.setBalance(inAmount);

        euint32 result = example.getBalance(bob);

        Permission memory permission = CFT.createPermissionSelf(bob);
        bytes32 sealingKey = CFT.createSealingKey(bobPKey);
        permission.sealingKey = sealingKey;
        permission = CFT.signPermissionSelf(permission, bobPKey);

        (bool allowed, bytes32 sealedOutput) = CFT.querySealOutput(
            euint32.unwrap(result),
            block.chainid,
            permission
        );

        assertEq(allowed, true);

        uint256 unsealed = CFT.unseal(sealedOutput, sealingKey);
        assertEq(unsealed, 100);
    }

    function test_permission() public {
        // Permission memory permission = CFT.createPermissionSelf(bob);
        // bytes32 sealingKey = CFT.createSealingKey(bobPKey);
        // permission.sealingKey = sealingKey;
        // permission = CFT.signPermissionSelf(permission, bobPKey);
        // bool isAllowed = CFT.acl().isAllowedWithPermission(permission, 0);
        // console.log("Is Allowed", isAllowed);
        // permission = Permission({
        //     issuer: 0x0376AAc07Ad725E01357B1725B5ceC61aE10473c,
        //     expiration: 10000000000,
        //     recipient: 0x0000000000000000000000000000000000000000,
        //     validatorId: 0,
        //     validatorContract: 0x0000000000000000000000000000000000000000,
        //     sealingKey: 0xf9f00615e0feb5664eb1b004bfb45f8183875b66a27b01cc0e649e6523e0a5ef,
        //     issuerSignature: hex"e0620e32f4e0900423ed3ae24becdf7a8c4e7f1eddc3b2341c632bec05023d97799ea8f2dfd5321c23b3bfc7777f9061fd9a10532577764c9f755ec34d89c2271c",
        //     recipientSignature: hex""
        // });
        // isAllowed = CFT.acl().isAllowedWithPermission(permission, 0);
        // console.log("Is Allowed", isAllowed);
    }

    function test_cofhejs_permission() public {
        // domain {
        //     name: 'ACL',
        //     version: '1',
        //     chainId: 31337n,
        //     verifyingContract: '0x36C02dA8a0983159322a80FFE9F24b1acfF8B570'
        // }
        // Permission {
        //     issuer: '0xB4E1decAd11798C446BcBed8C25b2f2923Fc1AC8',
        //     expiration: 1000000000000,
        //     recipient: '0x0000000000000000000000000000000000000000',
        //     validatorId: 0,
        //     validatorContract: '0x0000000000000000000000000000000000000000',
        //     issuerSignature: '0x27b576166d6bb4418cd2fdc7aeb3e9276189137c6f9b21495ea7f60e9f6ec5dc3ef3370bba34a36d4e32505d8eb46d5cb8a504756669e74925616e6971f191721c',
        //     recipientSignature: '0x',
        //     sealingKey: '0xf865839bb18600356eeb15aabb99ee115ad46d5d45d41e0ab1c662ee57715b13'
        // }
        // Permission memory permission = Permission({
        //     issuer: 0xB4E1decAd11798C446BcBed8C25b2f2923Fc1AC8,
        //     expiration: 1000000000000,
        //     recipient: 0x0000000000000000000000000000000000000000,
        //     validatorId: 0,
        //     validatorContract: 0x0000000000000000000000000000000000000000,
        //     issuerSignature: hex"27b576166d6bb4418cd2fdc7aeb3e9276189137c6f9b21495ea7f60e9f6ec5dc3ef3370bba34a36d4e32505d8eb46d5cb8a504756669e74925616e6971f191721c",
        //     recipientSignature: hex"",
        //     sealingKey: 0xf865839bb18600356eeb15aabb99ee115ad46d5d45d41e0ab1c662ee57715b13
        // });
        // euint32 amount = FHE.asEuint32(100);
        // bool isAllowed2 = CFT.acl().isAllowedWithPermission(
        //     permission,
        //     euint32.unwrap(amount)
        // );
        // console.log("Is Allowed 2", isAllowed2);
    }

    // function test_permission() public {
    //     Permission memory permission2 = Permission({
    //         issuer: 0x0376AAc07Ad725E01357B1725B5ceC61aE10473c,
    //         expiration: 10000000000,
    //         recipient: 0x0000000000000000000000000000000000000000,
    //         validatorId: 0,
    //         validatorContract: 0x0000000000000000000000000000000000000000,
    //         sealingKey: 0xf9f00615e0feb5664eb1b004bfb45f8183875b66a27b01cc0e649e6523e0a5ef,
    //         issuerSignature: hex"58660975f69cfd530e51550e7b86aec62e81101037ef2ddf4b3d80cdd256eef133816bc95b9e44732f7b97736cae67a71da0a68948699843215f03e951ad972b1b",
    //         recipientSignature: hex""
    //     });

    //     bool isAllowed2 = CFT.acl().isAllowedWithPermission(permission2, 0);
    //     console.log("Is Allowed (Permission 2)", isAllowed2);

    //     Permission memory permission = Permission({
    //         issuer: 0x4e6206fC78674E5eFf48Dcd0166060f95a832c60,
    //         expiration: 1000000000000,
    //         recipient: 0x0000000000000000000000000000000000000000,
    //         validatorId: 0,
    //         validatorContract: 0x0000000000000000000000000000000000000000,
    //         issuerSignature: hex"05d8577c0e922adcf472a885bbb6d18d329b528942034132048f5d1e42c949952aea82ee8e15873d676874ab4f6606d1623f282d52e0683e56efad7ba011bed21c",
    //         recipientSignature: hex"",
    //         sealingKey: 0x570e3f943655906c103fe71fa3fc15af65e157092e8e5499fc24a826e48c9019
    //     });

    //     bytes32 issuerHash = PermissionUtils.issuerHash(permission);
    //     bytes32 structHash = PermissionedUpgradeable(CFT.acl()).hashTypedDataV4(
    //         bytes32(0)
    //     );

    //     bool isAllowed = CFT.acl().isAllowedWithPermission(permission, 0);

    //     console.log("Is Allowed", isAllowed);

    //     console.log(
    //         "Last Handle",
    //         uint256(PermissionUtils.issuerHash(permission))
    //     );
    //     console.log("Struct Hash", uint256(structHash));

    //     (
    //         bytes1 fields,
    //         string memory name,
    //         string memory version,
    //         uint256 chainId,
    //         address verifyingContract,
    //         bytes32 salt,
    //         uint256[] memory extensions
    //     ) = PermissionedUpgradeable(CFT.acl()).eip712Domain();

    //     console.log("Name", name);
    //     console.log("Version", version);
    //     console.log("Chain Id", chainId);
    //     console.log("Verifying Contract", verifyingContract);
    // }
}
