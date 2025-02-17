// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.8.25 <0.9.0;
import "./ACL.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./ICofhe.sol";
import {MockCoFHE} from "./MockCoFHE.sol";

// Define an enum to represent the status of a key
enum KeyStatus {
    None,
    Valid,
    Error
}

struct KeyParams {
    bool isTriviallyEncrypted;
    int32 securityZone;
    uint8 uintType;
    KeyStatus status;
}

struct CiphertextKey {
    bool isTriviallyEncrypted;
    uint8 uintType;
    int32 securityZone;
    uint256 hash;
}

// Input validation errors
error InvalidInputsAmount(string operation, uint256 got, uint256 expected);
error InvalidOperationInputs(string operation);
error TooManyInputs(string operation, uint256 got, uint256 maxAllowed);
error InvalidBytesLength(uint256 got, uint256 expected);

// Type and security validation errors
error InvalidTypeOrSecurityZone(string operation);
error InvalidInputType(uint8 actual, uint8 expected);
error InvalidSecurityZone(int32 zone, int32 min, int32 max);
error InvalidSignature(uint256 ctHash);

// Access control errors
error InvalidAddress();
error OnlyAdminAllowed(address caller);
error OnlyAggregatorAllowed(address caller);

// Operation-specific errors
error RandomFunctionNotSupported();

library TMCommon {
    uint256 constant hashMaskForMetadata = type(uint256).max - type(uint16).max; // 2 bytes reserved for metadata
    uint256 constant securityZoneMask = type(uint8).max; // 0xff -  1 bytes reserved for security zone
    uint256 constant uintTypeMask = (type(uint8).max >> 1); // 0x7f - 7 bits reserved for uint type in the one before last byte
    uint256 constant triviallyEncryptedMask = type(uint8).max - uintTypeMask; //0x80  1 bit reserved for isTriviallyEncrypted
    uint256 constant shiftedTypeMask = uintTypeMask << 8; // 0x7f007 bits reserved for uint type in the one before last byte

    // Helper function for bytesToHexString
    function byteToChar(uint8 value) internal pure returns (bytes1) {
        if (value < 10) {
            return bytes1(uint8(48 + value)); // 0-9
        } else {
            return bytes1(uint8(87 + value)); // a-f
        }
    }

    function uint256ToBytes32(
        uint256 value
    ) internal pure returns (bytes memory) {
        bytes memory result = new bytes(32);
        assembly {
            mstore(add(result, 32), value)
        }
        return result;
    }

    function hashToString(uint256 value) internal pure returns (string memory) {
        return bytesToHexString(uint256ToBytes32(value));
    }

    function combineInputs(
        uint256[] memory encryptedHashes,
        uint256[] memory extraInputs
    ) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](
            encryptedHashes.length + extraInputs.length
        );
        uint i = 0;
        for (; i < encryptedHashes.length; i++) {
            inputs[i] = encryptedHashes[i];
        }
        for (; i < encryptedHashes.length + extraInputs.length; i++) {
            inputs[i] = extraInputs[i - encryptedHashes.length];
        }

        return inputs;
    }

    function getOnlyHashes(
        CiphertextKey[] memory inputs
    ) internal pure returns (uint256[] memory) {
        uint256[] memory hashes = new uint256[](inputs.length);
        for (uint i = 0; i < inputs.length; i++) {
            hashes[i] = inputs[i].hash;
        }
        return hashes;
    }

    function bytesToHexString(
        bytes memory buffer
    ) internal pure returns (string memory) {
        // Each byte takes 2 characters
        bytes memory hexChars = new bytes(buffer.length * 2);

        for (uint i = 0; i < buffer.length; i++) {
            uint8 value = uint8(buffer[i]);
            hexChars[i * 2] = byteToChar(value / 16);
            hexChars[i * 2 + 1] = byteToChar(value % 16);
        }

        return string(hexChars);
    }

    function bytesToUint256(bytes memory b) internal pure returns (uint256) {
        if (b.length != 32) {
            revert InvalidBytesLength(b.length, 32);
        }
        uint256 result;
        assembly {
            result := mload(add(b, 32))
        }
        return result;
    }

    function getReturnType(
        FunctionId functionId,
        uint8 ctType
    ) internal pure returns (uint8) {
        if (
            functionId == FunctionId.lte ||
            functionId == FunctionId.lt ||
            functionId == FunctionId.gte ||
            functionId == FunctionId.gt ||
            functionId == FunctionId.eq ||
            functionId == FunctionId.ne
        ) {
            return Utils.EBOOL_TFHE;
        }

        return ctType;
    }

    /// @notice Calculates the temporary hash for async operations
    /// @dev Must result the same temp hash as calculated by warp-drive/fhe-driver/CalcBinaryPlaceholderValueHash
    /// @param functionId - The function id
    /// @return The calculated temporary key
    function calcPlaceholderKey(
        uint8 ctType,
        int32 securityZone,
        uint256[] memory inputs,
        FunctionId functionId
    ) internal pure returns (uint256) {
        bytes memory combined;
        bool isTriviallyEncrypted = (functionId == FunctionId.trivialEncrypt);
        for (uint i = 0; i < inputs.length; i++) {
            combined = bytes.concat(combined, uint256ToBytes32(inputs[i]));
        }

        // Square is doing mul behind the scene
        if (functionId == FunctionId.square) {
            functionId = FunctionId.mul;
            combined = bytes.concat(combined, uint256ToBytes32(inputs[0]));
        }

        bytes1 functionIdByte = bytes1(uint8(functionId));
        combined = bytes.concat(combined, functionIdByte);

        // Calculate Keccak256 hash
        bytes32 hash = keccak256(combined);

        return
            _appendMetadata(
                uint256(hash),
                securityZone,
                getReturnType(functionId, ctType),
                isTriviallyEncrypted
            );
    }

    function getByteForTrivialAndType(
        bool isTrivial,
        uint8 uintType
    ) internal pure returns (uint256) {
        /// @dev first bit for isTriviallyEncrypted
        /// @dev last 7 bits for uintType

        return
            uint256(
                ((isTrivial ? triviallyEncryptedMask : 0x00) |
                    (uintType & uintTypeMask))
            );
    }

    /**
     * @dev ctHash format for user inputs is: TBD
     *      todo (eshel) add chain.id to the hash once decided
     *      fhe ops results format is: keccak256(operands_list, op)[0:29] || is_trivial (1 bit) & ct_type (7 bit) || securityZone || ct_version
     *      The CiphertextFHEList actually contains: 1 byte (= N) for size of handles_list, N bytes for the handles_types : 1 per handle, then the original fhe160list raw ciphertext
     */
    function _appendMetadata(
        uint256 preCtHash,
        int32 securityZone,
        uint8 uintType,
        bool isTrivial
    ) internal pure returns (uint256 result) {
        result = preCtHash & hashMaskForMetadata;
        uint256 metadata = (getByteForTrivialAndType(isTrivial, uintType) <<
            8) | (uint256(uint8(int8(securityZone)))); /// @dev 8 bits for type, 8 bits for securityZone
        result = result | metadata;
    }

    function getSecurityZoneFromHash(
        uint256 hash
    ) internal pure returns (int32) {
        return int32(int8(uint8(hash & securityZoneMask)));
    }

    function getUintTypeFromHash(uint256 hash) internal pure returns (uint8) {
        return uint8(hash & shiftedTypeMask);
    }

    function getSecAndTypeFromHash(
        uint256 hash
    ) internal pure returns (uint256) {
        return uint256((shiftedTypeMask | securityZoneMask) & hash);
    }
    function isTriviallyEncryptedFromHash(
        uint256 hash
    ) internal pure returns (bool) {
        return (hash & triviallyEncryptedMask) == triviallyEncryptedMask;
    }
}

contract TaskManager is ITaskManager, MockCoFHE {
    mapping(uint256 ctHash => uint256) private _decryptResult;
    mapping(uint256 ctHash => bool) private _decryptResultReady;

    // NOTE: MOCK
    mapping(uint256 ctHash => uint64) private _decryptResultReadyTimestamp;

    // Errors
    // Returned when the handle is not allowed in the ACL for the account.
    error ACLNotAllowed(uint256 handle, address account);

    // Returned when the decrypt result is not ready
    error DecryptResultNotReady(uint256 ctHash);

    // Events
    event TaskCreated(
        uint256 ctHash,
        string operation,
        uint256 input1,
        uint256 input2,
        uint256 input3
    );
    event DecryptRequest(
        uint256 ctHash,
        address callbackAddress,
        address requestor
    );
    event ProtocolNotification(
        uint256 ctHash,
        string operation,
        string errorMessage
    );

    struct Task {
        address creator;
        uint256 createdAt;
        bool isResultReady;
    }

    // Supported Security Zones
    int32 private securityZoneMax;
    int32 private securityZoneMin;

    // Address of the admin (deployer)
    address public admin;

    // Address of the aggregator
    address public aggregator;

    // Access-Control contract
    ACL public acl;

    // Modifier to restrict access to the admin only
    modifier onlyAdmin() {
        if (msg.sender != admin) {
            revert OnlyAdminAllowed(msg.sender);
        }
        _;
    }

    modifier onlyAggregator() {
        if (msg.sender != aggregator) {
            revert OnlyAggregatorAllowed(msg.sender);
        }
        _;
    }

    // Constructor to set the admin address
    constructor(address _admin, int32 minSZ, int32 maxSZ) {
        admin = _admin;
        securityZoneMin = minSZ;
        securityZoneMax = maxSZ;
    }

    function sendEventCreated(
        uint256 ctHash,
        string memory operation,
        uint256[] memory inputs
    ) private {
        if (inputs.length == 1) {
            emit TaskCreated(ctHash, operation, inputs[0], 0, 0);

            // NOTE: MOCK
            MOCK_unaryOperation(ctHash, operation, inputs[0]);
        } else if (inputs.length == 2) {
            emit TaskCreated(ctHash, operation, inputs[0], inputs[1], 0);

            // NOTE: MOCK
            MOCK_twoInputOperation(ctHash, operation, inputs[0], inputs[1]);
        } else {
            emit TaskCreated(
                ctHash,
                operation,
                inputs[0],
                inputs[1],
                inputs[2]
            );

            // NOTE: MOCK
            MOCK_threeInputOperation(
                ctHash,
                operation,
                inputs[0],
                inputs[1],
                inputs[2]
            );
        }
    }

    function createDecryptTask(uint256 ctHash, address requestor) public {
        checkAllowed(ctHash);
        emit DecryptRequest(ctHash, msg.sender, requestor);

        // NOTE: MOCK
        _decryptResultReady[ctHash] = false;
        _decryptResult[ctHash] = _get(ctHash);

        uint64 asyncOffset = uint64((block.timestamp % 10) + 1);
        _decryptResultReadyTimestamp[ctHash] =
            uint64(block.timestamp) +
            asyncOffset;
    }

    function getDecryptResult(uint256 ctHash) public view returns (uint256) {
        if (!_decryptResultReady[ctHash]) revert DecryptResultNotReady(ctHash);

        // NOTE: MOCK
        if (block.timestamp < _decryptResultReadyTimestamp[ctHash])
            revert DecryptResultNotReady(ctHash);

        return _get(ctHash);
    }

    function checkAllowed(uint256 ctHash) internal view {
        if (!TMCommon.isTriviallyEncryptedFromHash(ctHash)) {
            if (!acl.isAllowed(ctHash, msg.sender))
                revert ACLNotAllowed(ctHash, msg.sender);
        }
    }

    function isUnaryOperation(FunctionId funcId) internal pure returns (bool) {
        return funcId == FunctionId.not || funcId == FunctionId.square;
    }

    function isPlaintextOperation(
        FunctionId funcId
    ) internal pure returns (bool) {
        return
            funcId == FunctionId.random || funcId == FunctionId.trivialEncrypt;
    }

    function getSecurityZone(
        FunctionId functionId,
        uint256[] memory encryptedInputs,
        uint256[] memory plaintextInputs
    ) internal pure returns (int32) {
        if (isPlaintextOperation(functionId)) {
            // If inputs are plaintext (currently trivialEncrypt and random) the security zone will be the last input
            return int32(int256(plaintextInputs[plaintextInputs.length - 1]));
        }

        // First param of a function that receives some encrypted values will always be encrypted
        // Refer to: combineInput for more details
        return TMCommon.getSecurityZoneFromHash(encryptedInputs[0]);
    }

    function isValidSecurityZone(
        int32 _securityZone
    ) internal view returns (bool) {
        return
            _securityZone >= securityZoneMin &&
            _securityZone <= securityZoneMax;
    }

    function validateEncryptedHashes(
        uint256[] memory encryptedHashes
    ) internal view {
        for (uint i = 0; i < encryptedHashes.length; i++) {
            checkAllowed(encryptedHashes[i]);
        }
    }

    function validateInputs(
        uint256[] memory encryptedHashes,
        FunctionId funcId
    ) internal view {
        string memory functionName = Utils.functionIdToString(funcId);

        if (encryptedHashes.length == 0) {
            if (!isPlaintextOperation(funcId)) {
                revert InvalidOperationInputs(functionName);
            }
            return;
        }

        if (funcId == FunctionId.select) {
            validateSelectInputs(encryptedHashes);
        } else if (isUnaryOperation(funcId)) {
            if (encryptedHashes.length != 1) {
                revert InvalidInputsAmount(
                    functionName,
                    encryptedHashes.length,
                    1
                );
            }
        } else {
            if (encryptedHashes.length != 2) {
                revert InvalidInputsAmount(
                    functionName,
                    encryptedHashes.length,
                    2
                );
            }
            if (
                (
                    TMCommon.getSecAndTypeFromHash(
                        encryptedHashes[0] ^ encryptedHashes[1]
                    )
                ) != 0
            ) {
                revert InvalidTypeOrSecurityZone(functionName);
            }
        }

        int32 securityZone = TMCommon.getSecurityZoneFromHash(
            encryptedHashes[0]
        );
        if (!isValidSecurityZone(securityZone)) {
            revert InvalidSecurityZone(
                securityZone,
                securityZoneMin,
                securityZoneMax
            );
        }
        validateEncryptedHashes(encryptedHashes);
    }

    function validateSelectInputs(
        uint256[] memory encryptedHashes
    ) internal pure {
        if (encryptedHashes.length != 3) {
            revert InvalidInputsAmount("select", encryptedHashes.length, 3);
        }
        if (
            (
                TMCommon.getSecAndTypeFromHash(
                    encryptedHashes[1] ^ encryptedHashes[2]
                )
            ) != 0
        ) {
            revert InvalidTypeOrSecurityZone("select");
        }

        uint8 uintType = TMCommon.getUintTypeFromHash(encryptedHashes[0]);
        if ((uintType ^ Utils.EBOOL_TFHE) != 0) {
            revert InvalidInputType(uintType, Utils.EBOOL_TFHE);
        }
    }

    function createTask(
        uint8 returnType,
        FunctionId funcId,
        uint256[] memory encryptedHashes,
        uint256[] memory extraInputs
    ) external returns (uint256) {
        if (funcId == FunctionId.random) {
            revert RandomFunctionNotSupported();
        }
        uint256 inputsLength = encryptedHashes.length + extraInputs.length;
        if (inputsLength > 3) {
            revert TooManyInputs(
                Utils.functionIdToString(funcId),
                inputsLength,
                3
            );
        }

        validateInputs(encryptedHashes, funcId);
        uint256[] memory inputs = TMCommon.combineInputs(
            encryptedHashes,
            extraInputs
        );

        int32 securityZone = getSecurityZone(
            funcId,
            encryptedHashes,
            extraInputs
        );
        uint256 ctHash = TMCommon.calcPlaceholderKey(
            returnType,
            securityZone,
            inputs,
            funcId
        );

        acl.allowTransient(ctHash, msg.sender);
        sendEventCreated(ctHash, Utils.functionIdToString(funcId), inputs);

        return ctHash;
    }

    function handleDecryptResult(
        uint256 ctHash,
        uint256 result,
        address callbackContract,
        address requestor
    ) external onlyAggregator {
        // This call can be very expensive
        // TODO : Consider using allowance for gas fees and ask the user to pay for it
        _decryptResultReady[ctHash] = true;
        _decryptResult[ctHash] = result;
        _decryptResultReadyTimestamp[ctHash] = uint64(block.timestamp);
    }

    function handleError(
        uint256 ctHash,
        string memory operation,
        string memory errorMessage
    ) external onlyAggregator {
        emit ProtocolNotification(ctHash, operation, errorMessage);
    }

    function verifyType(uint8 ctType, uint8 desiredType) internal pure {
        if (ctType != desiredType) {
            revert InvalidInputType(ctType, desiredType);
        }
    }

    function verifyKey(
        uint256 ctHash,
        uint8 uintType,
        int32 securityZone,
        string memory signature,
        uint8 desiredType
    ) external {
        verifyType(uintType, desiredType);
        if (!isValidSecurityZone(securityZone)) {
            revert InvalidSecurityZone(
                securityZone,
                securityZoneMin,
                securityZoneMax
            );
        }
        if (!checkSignature(ctHash, uintType, securityZone, signature)) {
            revert InvalidSignature(ctHash);
        }

        acl.allowTransient(ctHash, msg.sender);

        // NOTE: MOCK
        MOCK_verifyKeyInStorage(ctHash);
    }

    function allow(uint256 ctHash, address account) external {
        if (!TMCommon.isTriviallyEncryptedFromHash(ctHash)) {
            acl.allow(ctHash, account, msg.sender);
        }
    }

    function allowTransient(uint256 ctHash, address account) external {
        if (!TMCommon.isTriviallyEncryptedFromHash(ctHash)) {
            acl.allowTransient(ctHash, account, msg.sender);
        }
    }

    function allowForDecryption(uint256 ctHash) external {
        if (!TMCommon.isTriviallyEncryptedFromHash(ctHash)) {
            uint256[] memory hashes = new uint256[](1);
            hashes[0] = ctHash;
            acl.allowForDecryption(hashes, msg.sender);
        }
    }

    function isAllowed(
        uint256 ctHash,
        address account
    ) external view returns (bool) {
        if (TMCommon.isTriviallyEncryptedFromHash(ctHash)) {
            return true;
        }
        return acl.isAllowed(ctHash, account);
    }

    function checkSignature(
        uint256 ctHash,
        uint8 uintType,
        int32 securityZone,
        string memory signature
    ) private pure returns (bool) {
        // TODO : Implement signature verification. signature should include user, securityZone and uintType
        uintType;
        securityZone;
        ctHash;
        signature;
        return true;
    }

    function setSecurityZoneMax(int32 securityZone) external onlyAdmin {
        if (securityZone < securityZoneMin) {
            revert InvalidSecurityZone(
                securityZone,
                securityZoneMin,
                securityZoneMax
            );
        }
        securityZoneMax = securityZone;
    }

    function setSecurityZoneMin(int32 securityZone) external onlyAdmin {
        if (securityZone > securityZoneMax) {
            revert InvalidSecurityZone(
                securityZone,
                securityZoneMin,
                securityZoneMax
            );
        }
        securityZoneMin = securityZone;
    }

    function setACLContract(address _aclAddress) external onlyAdmin {
        if (_aclAddress == address(0)) {
            revert InvalidAddress();
        }
        acl = ACL(_aclAddress);
    }

    function setAggregator(address _aggregatorAddress) external onlyAdmin {
        if (_aggregatorAddress == address(0)) {
            revert InvalidAddress();
        }
        aggregator = _aggregatorAddress;
    }

    // todo (eshel) remove for production, we don't have test for non-trivially encrypted cts yet.
    function simulateVerifyKey(uint256 ctHash, uint8, int32, uint8) external {
        acl.allowTransient(ctHash, msg.sender);
    }
}
