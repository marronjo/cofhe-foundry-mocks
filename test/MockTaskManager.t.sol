// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {CoFheTest} from "../src/CoFheTest.sol";
import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SimpleDecrypter {
    function decrypt(InEuint8 memory InEuint8Value) public {
        euint8 euint8Value = FHE.asEuint8(InEuint8Value);
        FHE.decrypt(euint8Value);
    }

    function decrypt(euint8 euint8Value) public {
        FHE.decrypt(euint8Value);
    }

    function getDecryptResult(uint256 ctHash) public view returns (uint256) {
        return FHE.getDecryptResult(ctHash);
    }
}

contract MockTaskManagerTests is Test {
    CoFheTest CFT;
    SimpleDecrypter simpleDecrypter;
    SimpleDecrypter thiefDecrypter;

    function setUp() public {
        CFT = new CoFheTest(false);

        simpleDecrypter = new SimpleDecrypter();
        thiefDecrypter = new SimpleDecrypter();
    }

    function test_mock_InEuintXX() public {
        {
            bool boolValue = true;
            InEbool memory InEboolValue = CFT.createInEbool(boolValue);
            CFT.assertHashValue(InEboolValue.ctHash, 1);

            ebool eboolValue = FHE.asEbool(InEboolValue);
            assertEq(InEboolValue.ctHash, ebool.unwrap(eboolValue));
        }

        {
            uint8 uint8Value = 10;
            InEuint8 memory InEuint8Value = CFT.createInEuint8(uint8Value);
            CFT.assertHashValue(InEuint8Value.ctHash, uint8Value);

            euint8 euint8Value = FHE.asEuint8(InEuint8Value);
            assertEq(InEuint8Value.ctHash, euint8.unwrap(euint8Value));
        }

        {
            uint16 uint16Value = 1000;
            InEuint16 memory InEuint16Value = CFT.createInEuint16(uint16Value);
            CFT.assertHashValue(InEuint16Value.ctHash, uint16Value);

            euint16 euint16Value = FHE.asEuint16(InEuint16Value);
            assertEq(InEuint16Value.ctHash, euint16.unwrap(euint16Value));
        }

        {
            uint32 uint32Value = 1000000;
            InEuint32 memory InEuint32Value = CFT.createInEuint32(uint32Value);
            CFT.assertHashValue(InEuint32Value.ctHash, uint32Value);

            euint32 euint32Value = FHE.asEuint32(InEuint32Value);
            assertEq(InEuint32Value.ctHash, euint32.unwrap(euint32Value));
        }

        {
            uint64 uint64Value = 1000000000;
            InEuint64 memory InEuint64Value = CFT.createInEuint64(uint64Value);
            CFT.assertHashValue(InEuint64Value.ctHash, uint64Value);

            euint64 euint64Value = FHE.asEuint64(InEuint64Value);
            assertEq(InEuint64Value.ctHash, euint64.unwrap(euint64Value));
        }

        {
            uint128 uint128Value = 1000000000000;
            InEuint128 memory InEuint128Value = CFT.createInEuint128(
                uint128Value
            );
            CFT.assertHashValue(InEuint128Value.ctHash, uint128Value);

            euint128 euint128Value = FHE.asEuint128(InEuint128Value);
            assertEq(InEuint128Value.ctHash, euint128.unwrap(euint128Value));
        }

        {
            uint256 uint256Value = 1000000000000000;
            InEuint256 memory InEuint256Value = CFT.createInEuint256(
                uint256Value
            );
            CFT.assertHashValue(InEuint256Value.ctHash, uint256Value);

            euint256 euint256Value = FHE.asEuint256(InEuint256Value);
            assertEq(InEuint256Value.ctHash, euint256.unwrap(euint256Value));
        }

        {
            address addressValue = 0x888888CfAebbEd5554c3F36BfBD233f822e9455f;
            InEaddress memory InEaddressValue = CFT.createInEaddress(
                addressValue
            );
            CFT.assertHashValue(
                InEaddressValue.ctHash,
                uint256(uint160(addressValue))
            );

            eaddress eaddressValue = FHE.asEaddress(InEaddressValue);
            assertEq(InEaddressValue.ctHash, eaddress.unwrap(eaddressValue));
        }
    }

    function test_mock_select() public {
        bool boolValue = true;
        ebool eboolValue = FHE.asEbool(boolValue);

        uint32 uint32A = 10;
        uint32 uint32B = 20;

        euint32 euintA = FHE.asEuint32(uint32A);
        euint32 euintB = FHE.asEuint32(uint32B);

        euint32 euintC = FHE.select(eboolValue, euintA, euintB);

        CFT.assertHashValue(euint32.unwrap(euintC), uint32A);

        boolValue = false;
        eboolValue = FHE.asEbool(boolValue);

        euintC = FHE.select(eboolValue, euintA, euintB);

        CFT.assertHashValue(euint32.unwrap(euintC), uint32B);
    }

    function test_mock_euint32_operations() public {
        uint32 a = 100;
        uint32 b = 50;

        // Convert to encrypted values
        euint32 ea = FHE.asEuint32(a);
        euint32 eb = FHE.asEuint32(b);

        // Test unary operations
        {
            // Test not (only works on ebool)
            ebool eboolVal = FHE.asEbool(true);
            ebool notResult = FHE.not(eboolVal);
            CFT.assertHashValue(notResult, false);
        }
        {
            // Test square
            euint32 squared = FHE.square(ea);
            CFT.assertHashValue(squared, a * a);
        }

        // Test two-input operations
        {
            // Arithmetic operations
            euint32 sum = FHE.add(ea, eb);
            CFT.assertHashValue(sum, a + b);
        }
        {
            // Test subtraction
            euint32 diff = FHE.sub(ea, eb);
            CFT.assertHashValue(diff, a - b);
        }
        {
            // Test multiplication
            euint32 prod = FHE.mul(ea, eb);
            CFT.assertHashValue(prod, a * b);
        }
        {
            // Test division
            euint32 div = FHE.div(ea, eb);
            CFT.assertHashValue(div, a / b);
        }
        {
            // Test remainder
            euint32 rem = FHE.rem(ea, eb);
            CFT.assertHashValue(rem, a % b);
        }

        // Bitwise operations
        {
            // Test bitwise AND
            euint32 andResult = FHE.and(ea, eb);
            CFT.assertHashValue(andResult, a & b);
        }
        {
            // Test bitwise OR
            euint32 orResult = FHE.or(ea, eb);
            CFT.assertHashValue(orResult, a | b);
        }
        {
            // Test bitwise XOR
            euint32 xorResult = FHE.xor(ea, eb);
            CFT.assertHashValue(xorResult, a ^ b);
        }

        // Shift operations
        uint32 shift = 2;
        {
            // Test shift left
            euint32 es = FHE.asEuint32(shift);

            euint32 shl = FHE.shl(ea, es);
            CFT.assertHashValue(shl, a << shift);
        }
        {
            // Test shift right
            euint32 es = FHE.asEuint32(shift);

            euint32 shr = FHE.shr(ea, es);
            CFT.assertHashValue(shr, a >> shift);
        }
        {
            // Test rol
            euint32 es = FHE.asEuint32(shift);

            euint32 rol = FHE.rol(ea, es);
            CFT.assertHashValue(rol, a << shift); // Note: rol is implemented as shl in the mock
        }
        {
            // Test ror
            euint32 es = FHE.asEuint32(shift);

            euint32 ror = FHE.ror(ea, es);
            CFT.assertHashValue(ror, a >> shift); // Note: ror is implemented as shr in the mock
        }

        // Comparison operations
        {
            // Test greater than
            ebool gt = FHE.gt(ea, eb);
            CFT.assertHashValue(gt, a > b);
        }
        {
            // Test less than
            ebool lt = FHE.lt(ea, eb);
            CFT.assertHashValue(lt, a < b);
        }
        {
            // Test greater than or equal to
            ebool gte = FHE.gte(ea, eb);
            CFT.assertHashValue(gte, a >= b);
        }
        {
            // Test less than or equal to
            ebool lte = FHE.lte(ea, eb);
            CFT.assertHashValue(lte, a <= b);
        }
        {
            // Test equal to
            ebool eq = FHE.eq(ea, eb);
            CFT.assertHashValue(eq, a == b);
        }
        {
            // Test not equal to
            ebool ne = FHE.ne(ea, eb);
            CFT.assertHashValue(ne, a != b);
        }

        // Min/Max operations
        {
            // Test min
            euint32 min = FHE.min(ea, eb);
            CFT.assertHashValue(min, a < b ? a : b);
        }
        {
            // Test max
            euint32 max = FHE.max(ea, eb);
            CFT.assertHashValue(max, a > b ? a : b);
        }
    }

    function test_mock_decrypt() public {
        uint160 userAddress = 512;

        uint8 uint8Value = 10;
        vm.prank(address(userAddress));
        InEuint8 memory InEuint8Value = CFT.createInEuint8(uint8Value);

        vm.prank(address(userAddress));
        simpleDecrypter.decrypt(InEuint8Value);

        // In mocks, this happens synchronously
        vm.warp(block.timestamp + 11);
        uint256 result = simpleDecrypter.getDecryptResult(InEuint8Value.ctHash);

        assertEq(result, uint8Value);
    }

    error ACLNotAllowed(uint256 handle, address account);

    function test_ACL_not_allowed() public {
        uint160 userAddress = 512;

        uint8 uint8Value = 10;
        vm.prank(address(userAddress));
        InEuint8 memory InEuint8Value = CFT.createInEuint8(uint8Value);

        vm.prank(address(userAddress));
        euint8 euint8Value = FHE.asEuint8(InEuint8Value);

        // Decrypt reverts (not allowed yet)

        vm.expectRevert(
            abi.encodeWithSelector(
                ACLNotAllowed.selector,
                InEuint8Value.ctHash,
                address(thiefDecrypter)
            )
        );

        thiefDecrypter.decrypt(euint8Value);

        // Allow decrypt

        vm.prank(address(userAddress));
        FHE.allow(euint8Value, address(thiefDecrypter));

        // Decrypt succeeds

        thiefDecrypter.decrypt(euint8Value);

        vm.warp(block.timestamp + 11);
        assertEq(
            thiefDecrypter.getDecryptResult(InEuint8Value.ctHash),
            uint8Value
        );
    }
}
