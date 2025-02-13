// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity >=0.8.25 <0.9.0;

import "@fhenixprotocol/cofhe-contracts/ICofhe.sol";
import {TMCommon} from "./MockTaskManager.sol";

/**
 * @dev Mock implementation of the CoFHE contract, used to test FHE ops in isolation.
 * Is inherited by MockTaskManager.
 *
 * It is responsible for storing a map of ctHash -> value
 * and for performing the operations on the values.
 *
 * It is intended as a 1:1 drop-in replacement for the real CoFHE coprocessor, with the following differences:
 * - AsyncCallbacks are called synchronously.
 * - Sealing is done symmetrically by XORing with a mask derived from the public key.
 * - Unencrypted values are available onchain via the `mockStorage` map.
 *
 * NOTE: This is not used in production
 */
abstract contract MockCoFHE {
    mapping(uint256 => uint256) public mockStorage;
    mapping(uint256 => bool) public inMockStorage;

    error InputNotInMockStorage(uint256 ctHash);

    // Used internally to check if we missed any operations in the mocks
    error InvalidUnaryOperation(string operation);
    error InvalidTwoInputOperation(string operation);
    error InvalidThreeInputOperation(string operation);

    // Utils

    function strEq(
        string memory _a,
        string memory _b
    ) internal pure returns (bool) {
        return
            keccak256(abi.encodePacked(_a)) == keccak256(abi.encodePacked(_b));
    }

    function opIs(
        string memory op,
        FunctionId fid
    ) internal pure returns (bool) {
        return strEq(op, Utils.functionIdToString(fid));
    }

    // Storage functions

    function _set(uint256 ctHash, uint256 value) internal {
        mockStorage[ctHash] = value;
        inMockStorage[ctHash] = true;
    }

    function _set(uint256 ctHash, bool value) internal {
        _set(ctHash, value ? 1 : 0);
    }

    function _get(uint256 ctHash) internal view returns (uint256) {
        if (!inMockStorage[ctHash]) revert InputNotInMockStorage(ctHash);
        return mockStorage[ctHash];
    }

    // Public functions

    function MOCK_replaceHash(uint256 oldHash, uint256 newHash) public {
        uint256 value = _get(oldHash);
        inMockStorage[oldHash] = false;
        mockStorage[oldHash] = 0;
        _set(newHash, value);
    }

    function MOCK_stripTrivialEncryptMask(
        uint256 ctHash
    ) public pure returns (uint256) {
        return ctHash & ~TMCommon.triviallyEncryptedMask;
    }

    // Mock functions

    function MOCK_verifyKeyInStorage(uint256 ctHash) internal view {
        if (!inMockStorage[ctHash]) revert InputNotInMockStorage(ctHash);
    }

    function MOCK_unaryOperation(
        uint256 ctHash,
        string memory operation,
        uint256 input
    ) internal {
        if (opIs(operation, FunctionId.random)) {
            _set(ctHash, uint256(blockhash(block.number - 1)));
            return;
        }
        if (opIs(operation, FunctionId.cast)) {
            _set(ctHash, _get(input));
            return;
        }
        if (opIs(operation, FunctionId.not)) {
            bool inputIsTruthy = _get(input) == 1;
            _set(ctHash, !inputIsTruthy);
            return;
        }
        if (opIs(operation, FunctionId.square)) {
            _set(ctHash, _get(input) * _get(input));
            return;
        }
        revert InvalidUnaryOperation(operation);
    }

    function MOCK_twoInputOperation(
        uint256 ctHash,
        string memory operation,
        uint256 input1,
        uint256 input2
    ) internal {
        if (opIs(operation, FunctionId.sub)) {
            _set(ctHash, _get(input1) - _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.add)) {
            _set(ctHash, _get(input1) + _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.xor)) {
            _set(ctHash, _get(input1) ^ _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.and)) {
            _set(ctHash, _get(input1) & _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.or)) {
            _set(ctHash, _get(input1) | _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.div)) {
            _set(ctHash, _get(input1) / _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.rem)) {
            _set(ctHash, _get(input1) % _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.mul)) {
            _set(ctHash, _get(input1) * _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.shl)) {
            _set(ctHash, _get(input1) << _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.shr)) {
            _set(ctHash, _get(input1) >> _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.gte)) {
            _set(ctHash, _get(input1) >= _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.lte)) {
            _set(ctHash, _get(input1) <= _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.lt)) {
            _set(ctHash, _get(input1) < _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.gt)) {
            _set(ctHash, _get(input1) > _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.min)) {
            uint256 min = _get(input1) < _get(input2)
                ? _get(input1)
                : _get(input2);
            _set(ctHash, min);
            return;
        }
        if (opIs(operation, FunctionId.max)) {
            uint256 max = _get(input1) > _get(input2)
                ? _get(input1)
                : _get(input2);
            _set(ctHash, max);
            return;
        }
        if (opIs(operation, FunctionId.eq)) {
            _set(ctHash, _get(input1) == _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.ne)) {
            _set(ctHash, _get(input1) != _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.rol)) {
            _set(ctHash, _get(input1) << _get(input2));
            return;
        }
        if (opIs(operation, FunctionId.ror)) {
            _set(ctHash, _get(input1) >> _get(input2));
            return;
        }
        revert InvalidTwoInputOperation(operation);
    }

    function MOCK_threeInputOperation(
        uint256 ctHash,
        string memory operation,
        uint256 input1,
        uint256 input2,
        uint256 input3
    ) internal {
        if (opIs(operation, FunctionId.trivialEncrypt)) {
            _set(ctHash, input1);
            return;
        }
        if (opIs(operation, FunctionId.select)) {
            _set(ctHash, _get(input1) == 1 ? _get(input2) : _get(input3));
            return;
        }
        revert InvalidThreeInputOperation(operation);
    }

    function MOCK_decryptOperation(
        uint256 ctHash,
        address requestor,
        address sender
    ) internal {
        IAsyncFHEReceiver(sender).handleDecryptResult(
            ctHash,
            _get(ctHash),
            requestor
        );
    }

    // Keccak256-based XOR shift.
    function MOCK_xorSeal(
        uint256 ctHash,
        bytes32 publicKey
    ) internal view returns (string memory) {
        bytes32 mask = keccak256(abi.encodePacked(publicKey));
        bytes32 xored = bytes32(_get(ctHash)) ^ mask;
        return bytes32ToHexString(xored);
    }

    function bytes32ToHexString(
        bytes32 data
    ) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(66);
        str[0] = "0";
        str[1] = "x";

        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = hexChars[uint8(data[i]) >> 4];
            str[3 + i * 2] = hexChars[uint8(data[i]) & 0x0f];
        }

        return string(str);
    }

    function MOCK_sealoutputOperation(
        uint256 ctHash,
        bytes32 publicKey,
        address requestor,
        address sender
    ) internal {
        string memory sealedOutput = MOCK_xorSeal(ctHash, publicKey);
        IAsyncFHEReceiver(sender).handleSealOutputResult(
            ctHash,
            sealedOutput,
            requestor
        );
    }
}
