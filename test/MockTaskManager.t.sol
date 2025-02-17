// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {CoFheTest} from "../src/CoFheTest.sol";
import "../src/FHE.sol";

contract SimpleDecrypter {
    function decrypt(inEuint8 memory inEuint8Value) public {
        euint8 euint8Value = FHE.asEuint8(inEuint8Value);
        FHE.decrypt(euint8Value);
    }

    function decrypt(euint8 euint8Value) public {
        FHE.decrypt(euint8Value);
    }

    function sealoutput(
        inEuint8 memory inEuint8Value,
        bytes32 publicKey
    ) public {
        euint8 euint8Value = FHE.asEuint8(inEuint8Value);
        FHE.sealoutput(euint8Value, publicKey);
    }

    function getDecryptedResult(uint256 ctHash) public view returns (uint256) {
        return FHE.getDecryptResult[ctHash];
    }
}

contract MockTaskManagerTests is Test {
    CoFheTest CFT;
    SimpleDecrypter simpleDecrypter;
    SimpleDecrypter thiefDecrypter;

    function setUp() public {
        CFT = new CoFheTest();

        simpleDecrypter = new SimpleDecrypter();
        thiefDecrypter = new SimpleDecrypter();
    }

    function _testTrivialEncrypt(uint8 utype, uint256 value) internal {
        uint256 ctHash = CFT.trivialEncrypt(utype, value);
        CFT.assertStoredValue(ctHash, value);
    }

    function test_mock_trivialEncrypt() public {
        _testTrivialEncrypt(Utils.EBOOL_TFHE, 1);
        _testTrivialEncrypt(Utils.EUINT8_TFHE, 10);
        _testTrivialEncrypt(Utils.EUINT16_TFHE, 1000);
        _testTrivialEncrypt(Utils.EUINT32_TFHE, 1000000);
        _testTrivialEncrypt(Utils.EUINT64_TFHE, 1000000000);
        _testTrivialEncrypt(Utils.EUINT128_TFHE, 1000000000000);
        _testTrivialEncrypt(Utils.EUINT256_TFHE, 1000000000000000);
        _testTrivialEncrypt(
            Utils.EADDRESS_TFHE,
            uint256(uint160(0x888888CfAebbEd5554c3F36BfBD233f822e9455f))
        );
    }

    function test_mock_inEuintXX() public {
        {
            bool boolValue = true;
            inEbool memory inEboolValue = CFT.createInEbool(boolValue);
            CFT.assertStoredValue(inEboolValue.hash, 1);

            ebool eboolValue = FHE.asEbool(inEboolValue);
            assertEq(inEboolValue.hash, ebool.unwrap(eboolValue));
        }

        {
            uint8 uint8Value = 10;
            inEuint8 memory inEuint8Value = CFT.createInEuint8(uint8Value);
            CFT.assertStoredValue(inEuint8Value.hash, uint8Value);

            euint8 euint8Value = FHE.asEuint8(inEuint8Value);
            assertEq(inEuint8Value.hash, euint8.unwrap(euint8Value));
        }

        {
            uint16 uint16Value = 1000;
            inEuint16 memory inEuint16Value = CFT.createInEuint16(uint16Value);
            CFT.assertStoredValue(inEuint16Value.hash, uint16Value);

            euint16 euint16Value = FHE.asEuint16(inEuint16Value);
            assertEq(inEuint16Value.hash, euint16.unwrap(euint16Value));
        }

        {
            uint32 uint32Value = 1000000;
            inEuint32 memory inEuint32Value = CFT.createInEuint32(uint32Value);
            CFT.assertStoredValue(inEuint32Value.hash, uint32Value);

            euint32 euint32Value = FHE.asEuint32(inEuint32Value);
            assertEq(inEuint32Value.hash, euint32.unwrap(euint32Value));
        }

        {
            uint64 uint64Value = 1000000000;
            inEuint64 memory inEuint64Value = CFT.createInEuint64(uint64Value);
            CFT.assertStoredValue(inEuint64Value.hash, uint64Value);

            euint64 euint64Value = FHE.asEuint64(inEuint64Value);
            assertEq(inEuint64Value.hash, euint64.unwrap(euint64Value));
        }

        {
            uint128 uint128Value = 1000000000000;
            inEuint128 memory inEuint128Value = CFT.createInEuint128(
                uint128Value
            );
            CFT.assertStoredValue(inEuint128Value.hash, uint128Value);

            euint128 euint128Value = FHE.asEuint128(inEuint128Value);
            assertEq(inEuint128Value.hash, euint128.unwrap(euint128Value));
        }

        {
            uint256 uint256Value = 1000000000000000;
            inEuint256 memory inEuint256Value = CFT.createInEuint256(
                uint256Value
            );
            CFT.assertStoredValue(inEuint256Value.hash, uint256Value);

            euint256 euint256Value = FHE.asEuint256(inEuint256Value);
            assertEq(inEuint256Value.hash, euint256.unwrap(euint256Value));
        }

        {
            address addressValue = 0x888888CfAebbEd5554c3F36BfBD233f822e9455f;
            inEaddress memory inEaddressValue = CFT.createInEaddress(
                addressValue
            );
            CFT.assertStoredValue(
                inEaddressValue.hash,
                uint256(uint160(addressValue))
            );

            eaddress eaddressValue = FHE.asEaddress(inEaddressValue);
            assertEq(inEaddressValue.hash, eaddress.unwrap(eaddressValue));
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

        CFT.assertStoredValue(euint32.unwrap(euintC), uint32A);

        boolValue = false;
        eboolValue = FHE.asEbool(boolValue);

        euintC = FHE.select(eboolValue, euintA, euintB);

        CFT.assertStoredValue(euint32.unwrap(euintC), uint32B);
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
            CFT.assertStoredValue(notResult, false);
        }
        {
            // Test square
            euint32 squared = FHE.square(ea);
            CFT.assertStoredValue(squared, a * a);
        }

        // Test two-input operations
        {
            // Arithmetic operations
            euint32 sum = FHE.add(ea, eb);
            CFT.assertStoredValue(sum, a + b);
        }
        {
            // Test subtraction
            euint32 diff = FHE.sub(ea, eb);
            CFT.assertStoredValue(diff, a - b);
        }
        {
            // Test multiplication
            euint32 prod = FHE.mul(ea, eb);
            CFT.assertStoredValue(prod, a * b);
        }
        {
            // Test division
            euint32 div = FHE.div(ea, eb);
            CFT.assertStoredValue(div, a / b);
        }
        {
            // Test remainder
            euint32 rem = FHE.rem(ea, eb);
            CFT.assertStoredValue(rem, a % b);
        }

        // Bitwise operations
        {
            // Test bitwise AND
            euint32 andResult = FHE.and(ea, eb);
            CFT.assertStoredValue(andResult, a & b);
        }
        {
            // Test bitwise OR
            euint32 orResult = FHE.or(ea, eb);
            CFT.assertStoredValue(orResult, a | b);
        }
        {
            // Test bitwise XOR
            euint32 xorResult = FHE.xor(ea, eb);
            CFT.assertStoredValue(xorResult, a ^ b);
        }

        // Shift operations
        uint32 shift = 2;
        {
            // Test shift left
            euint32 es = FHE.asEuint32(shift);

            euint32 shl = FHE.shl(ea, es);
            CFT.assertStoredValue(shl, a << shift);
        }
        {
            // Test shift right
            euint32 es = FHE.asEuint32(shift);

            euint32 shr = FHE.shr(ea, es);
            CFT.assertStoredValue(shr, a >> shift);
        }
        {
            // Test rol
            euint32 es = FHE.asEuint32(shift);

            euint32 rol = FHE.rol(ea, es);
            CFT.assertStoredValue(rol, a << shift); // Note: rol is implemented as shl in the mock
        }
        {
            // Test ror
            euint32 es = FHE.asEuint32(shift);

            euint32 ror = FHE.ror(ea, es);
            CFT.assertStoredValue(ror, a >> shift); // Note: ror is implemented as shr in the mock
        }

        // Comparison operations
        {
            // Test greater than
            ebool gt = FHE.gt(ea, eb);
            CFT.assertStoredValue(gt, a > b);
        }
        {
            // Test less than
            ebool lt = FHE.lt(ea, eb);
            CFT.assertStoredValue(lt, a < b);
        }
        {
            // Test greater than or equal to
            ebool gte = FHE.gte(ea, eb);
            CFT.assertStoredValue(gte, a >= b);
        }
        {
            // Test less than or equal to
            ebool lte = FHE.lte(ea, eb);
            CFT.assertStoredValue(lte, a <= b);
        }
        {
            // Test equal to
            ebool eq = FHE.eq(ea, eb);
            CFT.assertStoredValue(eq, a == b);
        }
        {
            // Test not equal to
            ebool ne = FHE.ne(ea, eb);
            CFT.assertStoredValue(ne, a != b);
        }

        // Min/Max operations
        {
            // Test min
            euint32 min = FHE.min(ea, eb);
            CFT.assertStoredValue(min, a < b ? a : b);
        }
        {
            // Test max
            euint32 max = FHE.max(ea, eb);
            CFT.assertStoredValue(max, a > b ? a : b);
        }
    }

    function test_mock_decrypt() public {
        uint160 userAddress = 512;

        uint8 uint8Value = 10;
        vm.prank(address(userAddress));
        inEuint8 memory inEuint8Value = CFT.createInEuint8(uint8Value);

        vm.prank(address(userAddress));
        simpleDecrypter.decrypt(inEuint8Value);

        // In mocks, this happens synchronously
        uint256 result = simpleDecrypter.decryptedRes(inEuint8Value.hash);

        assertEq(result, uint8Value);
    }

    function test_mock_sealOutput() public {
        uint160 userAddress = 512;

        uint8 uint8Value = 10;
        vm.prank(address(userAddress));
        inEuint8 memory inEuint8Value = CFT.createInEuint8(uint8Value);

        vm.prank(address(userAddress));
        bytes32 publicKey = bytes32("HELLO0x1234567890abcdef");
        simpleDecrypter.sealoutput(inEuint8Value, publicKey);

        // In mocks, this happens synchronously
        string memory result = simpleDecrypter.sealedRes(inEuint8Value.hash);

        uint256 unsealed = CFT.unseal(result, publicKey);
        assertEq(unsealed, uint8Value);
    }

    error ACLNotAllowed(uint256 handle, address account);

    function test_ACL_not_allowed() public {
        uint160 userAddress = 512;

        uint8 uint8Value = 10;
        vm.prank(address(userAddress));
        inEuint8 memory inEuint8Value = CFT.createInEuint8(uint8Value);
        euint8 euint8Value = FHE.asEuint8(inEuint8Value);

        // Decrypt reverts (not allowed yet)

        vm.expectRevert(
            abi.encodeWithSelector(
                ACLNotAllowed.selector,
                inEuint8Value.hash,
                address(thiefDecrypter)
            )
        );

        thiefDecrypter.decrypt(euint8Value);

        // Allow decrypt

        vm.prank(address(userAddress));
        FHE.allow(euint8Value, address(thiefDecrypter));

        // Decrypt succeeds

        thiefDecrypter.decrypt(euint8Value);

        assertEq(thiefDecrypter.decryptedRes(inEuint8Value.hash), uint8Value);
    }
}
