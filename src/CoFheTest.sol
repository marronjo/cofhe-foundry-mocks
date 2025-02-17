// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {TaskManager} from "./MockTaskManager.sol";
import {ACL} from "./ACL.sol";
import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CoFheTest is Test {
    TaskManager public taskManager;
    ACL public acl;

    address public constant TM_ADMIN = address(128);

    constructor() {
        etchFhenixMocks();
    }

    // SETUP

    function etchFhenixMocks() internal {
        deployCodeTo(
            "MockTaskManager.sol:TaskManager",
            abi.encode(TM_ADMIN, 0, 1),
            TASK_MANAGER_ADDRESS
        );
        taskManager = TaskManager(TASK_MANAGER_ADDRESS);

        acl = new ACL();
        vm.label(address(acl), "ACL");

        vm.prank(TM_ADMIN);
        taskManager.setACLContract(address(acl));
    }

    // EXPOSED FUNCTIONS

    /**
     * @notice              Returns the value of a given encrypted value from the mocked task manager.
     * @param ctHash        Hash of the encrypted value.
     * @return              Value of the encrypted value.
     */
    function mockStorage(uint256 ctHash) public view returns (uint256) {
        return taskManager.mockStorage(ctHash);
    }

    /**
     * @notice              Returns whether a given encrypted value is in the mocked task manager.
     * @param ctHash        Hash of the encrypted value.
     * @return              Whether the encrypted value is in the mocked task manager.
     */
    function inMockStorage(uint256 ctHash) public view returns (bool) {
        return taskManager.inMockStorage(ctHash);
    }

    // ASSERTIONS

    // Hash

    /**
     * @notice              Asserts that the value of a given encrypted value is equal to the expected value.
     * @param ctHash        Hash of the encrypted value.
     * @param value         Expected value.
     */
    function assertStoredValue(uint256 ctHash, uint256 value) public view {
        assertEq(taskManager.inMockStorage(ctHash), true);
        assertEq(taskManager.mockStorage(ctHash), value);
    }

    // Encrypted types
    function assertStoredValue(ebool eValue, bool value) public view {
        assertStoredValue(ebool.unwrap(eValue), value ? 1 : 0);
    }
    function assertStoredValue(euint8 eValue, uint8 value) public view {
        assertStoredValue(euint8.unwrap(eValue), value);
    }
    function assertStoredValue(euint16 eValue, uint16 value) public view {
        assertStoredValue(euint16.unwrap(eValue), value);
    }
    function assertStoredValue(euint32 eValue, uint32 value) public view {
        assertStoredValue(euint32.unwrap(eValue), value);
    }
    function assertStoredValue(euint64 eValue, uint64 value) public view {
        assertStoredValue(euint64.unwrap(eValue), value);
    }
    function assertStoredValue(euint128 eValue, uint128 value) public view {
        assertStoredValue(euint128.unwrap(eValue), value);
    }
    function assertStoredValue(eaddress eValue, address value) public view {
        assertStoredValue(eaddress.unwrap(eValue), uint256(uint160(value)));
    }

    // UTILS

    // Unseal a sealed value returned by FHE.sealoutput
    // In the mocked task manager, the sealed value is an xored value of the original value and a mask derived from the public key
    function unseal(
        string memory sealedData,
        bytes32 publicKey
    ) external pure returns (uint256 result) {
        bytes32 mask = keccak256(abi.encodePacked(publicKey));
        bytes32 xored = hexStringToBytes32(sealedData) ^ mask;
        return uint256(xored);
    }

    function hexStringToBytes32(
        string memory hexString
    ) public pure returns (bytes32) {
        require(
            bytes(hexString).length == 66 &&
                bytes(hexString)[0] == "0" &&
                bytes(hexString)[1] == "x",
            "Invalid hex string"
        );

        bytes32 result;
        for (uint256 i = 2; i < 66; i++) {
            result =
                (result << 4) |
                bytes32(uint256(fromHexChar(uint8(bytes(hexString)[i]))));
        }
        return result;
    }

    function fromHexChar(uint8 c) internal pure returns (uint8) {
        if (c >= 48 && c <= 57) {
            return c - 48; // '0' - '9'
        } else if (c >= 97 && c <= 102) {
            return c - 87; // 'a' - 'f'
        } else if (c >= 65 && c <= 70) {
            return c - 55; // 'A' - 'F'
        } else {
            revert("Invalid hex char");
        }
    }

    /**
     * @notice              Creates an encrypted value of a given type. The hash returned is a pointer to the value in the mocked CoFHE.
     * @param utype         Type of the encrypted value.
     * @param value         Value to encrypt.
     * @return              Hash pointer to the encrypted value.
     */
    function trivialEncrypt(
        uint8 utype,
        uint256 value
    ) public returns (uint256) {
        vm.prank(msg.sender);
        if (utype == Utils.EBOOL_TFHE) {
            return ebool.unwrap(FHE.asEbool(value == 1));
        } else if (utype == Utils.EUINT8_TFHE) {
            return euint8.unwrap(FHE.asEuint8(uint8(value)));
        } else if (utype == Utils.EUINT16_TFHE) {
            return euint16.unwrap(FHE.asEuint16(uint16(value)));
        } else if (utype == Utils.EUINT32_TFHE) {
            return euint32.unwrap(FHE.asEuint32(uint32(value)));
        } else if (utype == Utils.EUINT64_TFHE) {
            return euint64.unwrap(FHE.asEuint64(uint64(value)));
        } else if (utype == Utils.EUINT128_TFHE) {
            return euint128.unwrap(FHE.asEuint128(uint128(value)));
        } else if (utype == Utils.EUINT256_TFHE) {
            return euint256.unwrap(FHE.asEuint256(uint256(value)));
        } else if (utype == Utils.EADDRESS_TFHE) {
            return eaddress.unwrap(FHE.asEaddress(address(uint160(value))));
        } else {
            revert("Invalid utype");
        }
    }

    /**
     * @notice                  Strips the trivial encrypt mask from a given hash.
     * @param ctHash            Hash of the encrypted value.
     * @return strippedCtHash   Stripped hash.
     */
    function stripTrivialEncryptMask(
        uint256 ctHash
    ) internal returns (uint256 strippedCtHash) {
        // Strip the trivial encrypt mask
        strippedCtHash = taskManager.MOCK_stripTrivialEncryptMask(ctHash);

        // Replace the hash with the stripped hash in storage
        taskManager.MOCK_replaceHash(ctHash, strippedCtHash);
    }

    function createEncryptedInput(
        uint8 utype,
        uint256 value,
        int32 securityZone
    ) internal returns (bytes memory) {
        uint256 ctHash = trivialEncrypt(utype, value);
        uint256 strippedCtHash = stripTrivialEncryptMask(ctHash);
        return
            abi.encode(
                securityZone,
                strippedCtHash,
                utype,
                "MOCK" // signature
            );
    }

    // Derived functions that use the generic create

    /**
     * @notice              Creates an inEbool to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEbool.
     */
    function createInEbool(
        bool value,
        int32 securityZone
    ) public returns (inEbool memory) {
        return
            abi.decode(
                createEncryptedInput(
                    Utils.EBOOL_TFHE,
                    value ? 1 : 0,
                    securityZone
                ),
                (inEbool)
            );
    }

    /**
     * @notice              Creates an inEuint8 to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEuint8.
     */
    function createInEuint8(
        uint8 value,
        int32 securityZone
    ) public returns (inEuint8 memory) {
        return
            abi.decode(
                createEncryptedInput(Utils.EUINT8_TFHE, value, securityZone),
                (inEuint8)
            );
    }

    /**
     * @notice              Creates an inEuint16 to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEuint16.
     */
    function createInEuint16(
        uint16 value,
        int32 securityZone
    ) public returns (inEuint16 memory) {
        return
            abi.decode(
                createEncryptedInput(Utils.EUINT16_TFHE, value, securityZone),
                (inEuint16)
            );
    }

    /**
     * @notice              Creates an inEuint32 to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEuint32.
     */
    function createInEuint32(
        uint32 value,
        int32 securityZone
    ) public returns (inEuint32 memory) {
        return
            abi.decode(
                createEncryptedInput(Utils.EUINT32_TFHE, value, securityZone),
                (inEuint32)
            );
    }

    /**
     * @notice              Creates an inEuint64 to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEuint64.
     */
    function createInEuint64(
        uint64 value,
        int32 securityZone
    ) public returns (inEuint64 memory) {
        return
            abi.decode(
                createEncryptedInput(Utils.EUINT64_TFHE, value, securityZone),
                (inEuint64)
            );
    }

    /**
     * @notice              Creates an inEuint128 to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEuint128.
     */
    function createInEuint128(
        uint128 value,
        int32 securityZone
    ) public returns (inEuint128 memory) {
        return
            abi.decode(
                createEncryptedInput(Utils.EUINT128_TFHE, value, securityZone),
                (inEuint128)
            );
    }

    /**
     * @notice              Creates an inEuint256 to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEuint256.
     */
    function createInEuint256(
        uint256 value,
        int32 securityZone
    ) public returns (inEuint256 memory) {
        return
            abi.decode(
                createEncryptedInput(Utils.EUINT256_TFHE, value, securityZone),
                (inEuint256)
            );
    }

    /**
     * @notice              Creates an inEaddress to be used as FHE input. Value is stored in MockCoFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              inEaddress.
     */
    function createInEaddress(
        address value,
        int32 securityZone
    ) public returns (inEaddress memory) {
        return
            abi.decode(
                createEncryptedInput(
                    Utils.EADDRESS_TFHE,
                    uint256(uint160(value)),
                    securityZone
                ),
                (inEaddress)
            );
    }

    // Overloads with default securityZone=0 for backward compatibility

    function createInEbool(bool value) public returns (inEbool memory) {
        return createInEbool(value, 0);
    }

    function createInEuint8(uint8 value) public returns (inEuint8 memory) {
        return createInEuint8(value, 0);
    }

    function createInEuint16(uint16 value) public returns (inEuint16 memory) {
        return createInEuint16(value, 0);
    }

    function createInEuint32(uint32 value) public returns (inEuint32 memory) {
        return createInEuint32(value, 0);
    }

    function createInEuint64(uint64 value) public returns (inEuint64 memory) {
        return createInEuint64(value, 0);
    }

    function createInEuint128(
        uint128 value
    ) public returns (inEuint128 memory) {
        return createInEuint128(value, 0);
    }

    function createInEuint256(
        uint256 value
    ) public returns (inEuint256 memory) {
        return createInEuint256(value, 0);
    }

    function createInEaddress(
        address value
    ) public returns (inEaddress memory) {
        return createInEaddress(value, 0);
    }
}
