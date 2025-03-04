// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {TaskManager} from "./MockTaskManager.sol";
import {EncryptedInput} from "./MockCoFHE.sol";
import {ACL} from "./ACL.sol";
import "./FHE.sol";
import {MockZkVerifier} from "./MockZkVerifier.sol";
import {ZK_VERIFIER_ADDRESS} from "./addresses/ZkVerifierAddress.sol";

contract CoFheTest is Test {
    TaskManager public taskManager;
    MockZkVerifier public zkVerifier;
    ACL public acl;
    bool private _log;

    address public constant TM_ADMIN = address(128);

    constructor(bool log) {
        _log = log;
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
        vm.label(address(taskManager), "TaskManager(Mock)");

        deployCodeTo("MockZkVerifier.sol:MockZkVerifier", ZK_VERIFIER_ADDRESS);
        zkVerifier = MockZkVerifier(ZK_VERIFIER_ADDRESS);
        vm.label(address(zkVerifier), "MockZkVerifier");

        acl = new ACL();
        vm.label(address(acl), "ACL");

        vm.prank(TM_ADMIN);
        taskManager.setACLContract(address(acl));

        // Set log setting
        taskManager.setLogOps(_log);
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

    function createEncryptedInput(
        uint8 utype,
        uint256 value,
        int32 securityZone
    ) internal returns (bytes memory) {
        EncryptedInput memory input = zkVerifier.zkVerify(
            utype,
            value,
            msg.sender,
            securityZone
        );
        return abi.encode(securityZone, input.hash, utype, input.signature);
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
