// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {TaskManager} from "./MockTaskManager.sol";
import {EncryptedInput} from "./MockCoFHE.sol";
import {ACL} from "./ACL.sol";
import "./FHE.sol";
import {MockZkVerifier} from "./MockZkVerifier.sol";
import {MockZkVerifierSigner} from "./MockZkVerifierSigner.sol";
import {ZK_VERIFIER_ADDRESS, ZK_VERIFIER_SIGNER_ADDRESS} from "./addresses/ZkVerifierAddress.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Permission, PermissionUtils} from "./Permissioned.sol";
import {MockQueryDecrypter} from "./MockQueryDecrypter.sol";
import {QUERY_DECRYPTER_ADDRESS} from "./addresses/QueryDecrypterAddress.sol";

contract CoFheTest is Test {
    TaskManager public taskManager;
    MockZkVerifier public zkVerifier;
    MockZkVerifierSigner public zkVerifierSigner;
    ACL public acl;
    MockQueryDecrypter public queryDecrypter;

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

        deployCodeTo(
            "MockZkVerifierSigner.sol:MockZkVerifierSigner",
            ZK_VERIFIER_SIGNER_ADDRESS
        );
        zkVerifierSigner = MockZkVerifierSigner(ZK_VERIFIER_SIGNER_ADDRESS);
        vm.label(address(zkVerifierSigner), "MockZkVerifierSigner");

        acl = new ACL();
        acl.initialize(TM_ADMIN);
        vm.label(address(acl), "ACL");

        vm.prank(TM_ADMIN);
        taskManager.setACLContract(address(acl));

        deployCodeTo(
            "MockQueryDecrypter.sol:MockQueryDecrypter",
            QUERY_DECRYPTER_ADDRESS
        );
        queryDecrypter = MockQueryDecrypter(QUERY_DECRYPTER_ADDRESS);
        vm.label(address(queryDecrypter), "MockQueryDecrypter");

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
    function assertHashValue(uint256 ctHash, uint256 value) public view {
        assertEq(taskManager.inMockStorage(ctHash), true);
        assertEq(taskManager.mockStorage(ctHash), value);
    }
    function assertHashValue(
        uint256 ctHash,
        uint256 value,
        string memory message
    ) public view {
        assertEq(taskManager.inMockStorage(ctHash), true, message);
        assertEq(taskManager.mockStorage(ctHash), value, message);
    }

    // Encrypted types (no message)

    function assertHashValue(ebool eValue, bool value) public view {
        assertHashValue(ebool.unwrap(eValue), value ? 1 : 0);
    }
    function assertHashValue(euint8 eValue, uint8 value) public view {
        assertHashValue(euint8.unwrap(eValue), value);
    }
    function assertHashValue(euint16 eValue, uint16 value) public view {
        assertHashValue(euint16.unwrap(eValue), value);
    }
    function assertHashValue(euint32 eValue, uint32 value) public view {
        assertHashValue(euint32.unwrap(eValue), value);
    }
    function assertHashValue(euint64 eValue, uint64 value) public view {
        assertHashValue(euint64.unwrap(eValue), value);
    }
    function assertHashValue(euint128 eValue, uint128 value) public view {
        assertHashValue(euint128.unwrap(eValue), value);
    }
    function assertHashValue(eaddress eValue, address value) public view {
        assertHashValue(eaddress.unwrap(eValue), uint256(uint160(value)));
    }

    // Encrypted types (with message)

    function assertHashValue(
        ebool eValue,
        bool value,
        string memory message
    ) public view {
        assertHashValue(ebool.unwrap(eValue), value ? 1 : 0, message);
    }
    function assertHashValue(
        euint8 eValue,
        uint8 value,
        string memory message
    ) public view {
        assertHashValue(euint8.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint16 eValue,
        uint16 value,
        string memory message
    ) public view {
        assertHashValue(euint16.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint32 eValue,
        uint32 value,
        string memory message
    ) public view {
        assertHashValue(euint32.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint64 eValue,
        uint64 value,
        string memory message
    ) public view {
        assertHashValue(euint64.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint128 eValue,
        uint128 value,
        string memory message
    ) public view {
        assertHashValue(euint128.unwrap(eValue), value, message);
    }
    function assertHashValue(
        eaddress eValue,
        address value,
        string memory message
    ) public view {
        assertHashValue(
            eaddress.unwrap(eValue),
            uint256(uint160(value)),
            message
        );
    }

    // UTILS

    function createEncryptedInput(
        uint8 utype,
        uint256 value,
        int32 securityZone
    ) internal returns (bytes memory) {
        uint256 chainId = uint256(block.chainid);

        // Create input
        EncryptedInput memory input = zkVerifier.zkVerify(
            value,
            utype,
            msg.sender,
            securityZone,
            chainId
        );

        // Sign input
        input = zkVerifierSigner.zkVerifySign(input);

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

    // PERMISSIONS

    bytes32 private constant PERMISSION_TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    function permissionDomainSeparator() internal view returns (bytes32) {
        string memory name;
        string memory version;
        uint256 chainId;
        address verifyingContract;

        (, name, version, chainId, verifyingContract, , ) = acl.eip712Domain();

        return
            keccak256(
                abi.encode(
                    PERMISSION_TYPE_HASH,
                    keccak256(bytes(name)),
                    keccak256(bytes(version)),
                    chainId,
                    verifyingContract
                )
            );
    }

    function permissionHashTypedDataV4(
        bytes32 structHash
    ) public view returns (bytes32) {
        return
            MessageHashUtils.toTypedDataHash(
                permissionDomainSeparator(),
                structHash
            );
    }

    function signPermission(
        bytes32 structHash,
        uint256 pkey
    ) public pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkey, structHash);
        return abi.encodePacked(r, s, v); // note the order here is different from line above.
    }

    function signPermissionSelf(
        Permission memory permission,
        uint256 pkey
    ) public view returns (Permission memory signedPermission) {
        signedPermission = permission;

        bytes32 permissionHash = PermissionUtils.issuerSelfHash(permission);
        bytes32 structHash = permissionHashTypedDataV4(permissionHash);

        signedPermission.issuerSignature = signPermission(structHash, pkey);
    }

    function signPermissionShared(
        Permission memory permission,
        uint256 pkey
    ) public view returns (Permission memory signedPermission) {
        signedPermission = permission;
        bytes32 permissionHash = PermissionUtils.issuerSharedHash(permission);
        bytes32 structHash = permissionHashTypedDataV4(permissionHash);

        signedPermission.issuerSignature = signPermission(structHash, pkey);
    }

    function signPermissionRecipient(
        Permission memory permission,
        uint256 pkey
    ) public view returns (Permission memory signedPermission) {
        signedPermission = permission;

        bytes32 permissionHash = PermissionUtils.recipientHash(permission);
        bytes32 structHash = permissionHashTypedDataV4(permissionHash);

        signedPermission.recipientSignature = signPermission(structHash, pkey);
    }

    function createBasePermission()
        public
        pure
        returns (Permission memory permission)
    {
        permission = Permission({
            issuer: address(0),
            expiration: 10000000000,
            recipient: address(0),
            validatorId: 0,
            validatorContract: address(0),
            sealingKey: bytes32(0),
            issuerSignature: new bytes(0),
            recipientSignature: new bytes(0)
        });
    }

    function createPermissionSelf(
        address issuer
    ) public pure returns (Permission memory permission) {
        permission = createBasePermission();
        permission.issuer = issuer;
    }

    function createPermissionShared(
        address issuer,
        address recipient
    ) public pure returns (Permission memory permission) {
        permission = createBasePermission();
        permission.issuer = issuer;
        permission.recipient = recipient;
    }

    function createSealingKey(uint256 seed) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(seed));
    }

    function queryDecrypt(
        Permission memory permission,
        uint256 ctHash
    ) public view returns (uint256) {
        return queryDecrypter.queryDecrypt(permission, ctHash);
    }

    function querySealOutput(
        Permission memory permission,
        uint256 ctHash
    ) public view returns (bytes32) {
        return queryDecrypter.querySealOutput(permission, ctHash);
    }

    function unseal(bytes32 hashed, bytes32 key) public view returns (uint256) {
        return queryDecrypter.unseal(hashed, key);
    }
}
