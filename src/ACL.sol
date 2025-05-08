// SPDX-License-Identifier: BSD-3-Clause-Clear
// solhint-disable-next-line transient-storage
pragma solidity >=0.8.25 <0.9.0;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {MockPermissioned, Permission} from "./Permissioned.sol";
import {TASK_MANAGER_ADDRESS} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * @title  ACL
 * @notice The ACL (Access Control List) is a permission management system designed to
 *         control who can access, compute on, or decrypt encrypted values in cofhe.
 *         By defining and enforcing these permissions, the ACL ensures that encrypted data remains secure while still being usable
 *         within authorized contexts.
 */
contract ACL is Ownable2Step, MockPermissioned {
    /// @notice Returned if the delegatee contract is already delegatee for sender & delegator addresses.
    error AlreadyDelegated();

    /// @notice Returned if the sender is the delegatee address.
    error SenderCannotBeDelegateeAddress();

    /// @notice         Returned if the sender address is not allowed for allow operations.
    /// @param sender   Sender address.
    error SenderNotAllowed(address sender);

    /// @notice         Returned if the user is trying to directly allow a handle (not via Task Manager).
    /// @param sender   Sender address.
    error DirectAllowForbidden(address sender);

    /// @notice             Emitted when a list of handles is allowed for decryption.
    /// @param handlesList  List of handles allowed for decryption.
    event AllowedForDecryption(uint256[] handlesList);

    /// @notice                 Emitted when a new delegate address is added.
    /// @param sender           Sender address
    /// @param delegatee        Delegatee address.
    /// @param contractAddress  Contract address.
    event NewDelegation(
        address indexed sender,
        address indexed delegatee,
        address indexed contractAddress
    );

    /// @custom:storage-location erc7201:cofhe.storage.ACL
    struct ACLStorage {
        mapping(uint256 handle => bool isGlobal) globalHandles;
        mapping(uint256 handle => mapping(address account => bool isAllowed)) persistedAllowedPairs;
        mapping(uint256 => bool) allowedForDecryption;
        mapping(address account => mapping(address delegatee => mapping(address contractAddress => bool isDelegate))) delegates;
    }

    /// @notice Name of the contract.
    string private constant CONTRACT_NAME = "ACL";

    /// @notice Major version of the contract.
    uint256 private constant MAJOR_VERSION = 0;

    /// @notice Minor version of the contract.
    uint256 private constant MINOR_VERSION = 1;

    /// @notice Patch version of the contract.
    uint256 private constant PATCH_VERSION = 0;

    /// @notice TaskManagerAddress address.
    address public constant TASK_MANAGER_ADDRESS_ = TASK_MANAGER_ADDRESS;

    /// @dev keccak256(abi.encode(uint256(keccak256("cofhe.storage.ACL")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ACL_SLOT =
        keccak256(abi.encode(uint256(keccak256("cofhe.storage.ACL")) - 1)) &
            ~bytes32(uint256(0xff));

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address initialOwner
    ) MockPermissioned() Ownable(initialOwner) {}

    function exists() public pure returns (bool) {
        return true;
    }

    /**
     * @notice              Allows the use of `handle` for the address `account`.
     * @dev                 The caller must be allowed to use `handle` for allow() to succeed. If not, allow() reverts.
     * @param handle        Handle.
     * @param account       Address of the account being given permissions.
     * @param requester     Address of the account giving the permissions.
     */
    function allow(
        uint256 handle,
        address account,
        address requester
    ) public virtual {
        if (msg.sender != TASK_MANAGER_ADDRESS_) {
            revert DirectAllowForbidden(msg.sender);
        }

        if (!isAllowed(handle, requester)) {
            revert SenderNotAllowed(requester);
        }

        ACLStorage storage $ = _getACLStorage();
        $.persistedAllowedPairs[handle][account] = true;
    }

    /**
     * @notice              Allows the use of `handle` globally (all accounts).
     * @dev                 The caller must be allowed to use `handle` for allowGlobal() to succeed. If not, allowGlobal() reverts.
     * @param handle        Handle.
     * @param requester     Address of the account giving the permissions.
     */
    function allowGlobal(uint256 handle, address requester) public virtual {
        if (msg.sender != TASK_MANAGER_ADDRESS_) {
            revert DirectAllowForbidden(msg.sender);
        }

        if (!isAllowed(handle, requester)) {
            revert SenderNotAllowed(requester);
        }

        ACLStorage storage $ = _getACLStorage();

        $.globalHandles[handle] = true;
    }

    /**
     * @notice              Allows a list of handles to be decrypted.
     * @param handlesList   List of handles.
     */
    function allowForDecryption(
        uint256[] memory handlesList,
        address requester
    ) public virtual {
        if (msg.sender != TASK_MANAGER_ADDRESS_) {
            revert DirectAllowForbidden(msg.sender);
        }

        uint256 len = handlesList.length;
        ACLStorage storage $ = _getACLStorage();

        for (uint256 k = 0; k < len; k++) {
            uint256 handle = handlesList[k];
            if (!isAllowed(handle, requester)) {
                revert SenderNotAllowed(requester);
            }
            $.allowedForDecryption[handle] = true;
        }
        emit AllowedForDecryption(handlesList);
    }

    /**
     * @notice              Allows the use of `handle` by address `account` for this transaction.
     * @dev                 The caller must be the Task Manager contract.
     * @dev                 The requester must be allowed to use `handle` for allowTransient() to succeed.
     *                      If not, allowTransient() reverts.
     * @param handle        Handle.
     * @param account       Address of the account.
     * @param requester     Address of the requester.
     */
    function allowTransient(
        uint256 handle,
        address account,
        address requester
    ) public virtual {
        if (msg.sender != TASK_MANAGER_ADDRESS_) {
            revert DirectAllowForbidden(msg.sender);
        }

        if (
            !isAllowed(handle, requester) && requester != TASK_MANAGER_ADDRESS_
        ) {
            revert SenderNotAllowed(requester);
        }

        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            // solc-ignore-next-line transient-storage
            tstore(key, 1)
            let length := tload(0)
            let lengthPlusOne := add(length, 1)
            // solc-ignore-next-line transient-storage
            tstore(lengthPlusOne, key)
            // solc-ignore-next-line transient-storage
            tstore(0, lengthPlusOne)
        }
    }

    /**
     * @notice                  Delegates the access of `handles` in the context of account abstraction for issuing
     *                          reencryption requests from a smart contract account.
     * @param delegatee         Delegatee address.
     * @param delegateeContract Delegatee contract.
     */
    function delegateAccount(
        address delegatee,
        address delegateeContract
    ) public virtual {
        if (msg.sender != TASK_MANAGER_ADDRESS_) {
            revert DirectAllowForbidden(msg.sender);
        }
        if (delegateeContract == msg.sender) {
            revert SenderCannotBeDelegateeAddress();
        }

        ACLStorage storage $ = _getACLStorage();
        if ($.delegates[msg.sender][delegatee][delegateeContract]) {
            revert AlreadyDelegated();
        }

        $.delegates[msg.sender][delegatee][delegateeContract] = true;
        emit NewDelegation(msg.sender, delegatee, delegateeContract);
    }

    /**
     * @notice                  Returns whether the delegatee is allowed to access the handle.
     * @param delegatee         Delegatee address.
     * @param handle            Handle.
     * @param contractAddress   Contract address.
     * @param account           Address of the account.
     * @return isAllowed        Whether the handle can be accessed.
     */
    function allowedOnBehalf(
        address delegatee,
        uint256 handle,
        address contractAddress,
        address account
    ) public view virtual returns (bool) {
        ACLStorage storage $ = _getACLStorage();
        return
            $.persistedAllowedPairs[handle][account] &&
            $.persistedAllowedPairs[handle][contractAddress] &&
            $.delegates[account][delegatee][contractAddress];
    }

    /**
     * @notice                      Checks whether the account is allowed to use the handle in the
     *                              same transaction (transient).
     * @param handle                Handle.
     * @param account               Address of the account.
     * @return isAllowedTransient   Whether the account can access transiently the handle.
     */
    function allowedTransient(
        uint256 handle,
        address account
    ) public view virtual returns (bool) {
        bool isAllowedTransient;
        bytes32 key = keccak256(abi.encodePacked(handle, account));
        assembly {
            isAllowedTransient := tload(key)
        }
        return isAllowedTransient;
    }

    /**
     * @notice                     Getter function for the TaskManager contract address.
     * @return taskManagerAddress  Address of the TaskManager.
     */
    function getTaskManagerAddress() public view virtual returns (address) {
        return TASK_MANAGER_ADDRESS_;
    }

    /**
     * @notice              Returns whether the account is allowed to use the `handle`, either due to
     *                      allowTransient() or allow().
     * @param handle        Handle.
     * @param account       Address of the account.
     * @return isAllowed    Whether the account can access the handle.
     */
    function isAllowed(
        uint256 handle,
        address account
    ) public view virtual returns (bool) {
        return
            allowedTransient(handle, account) ||
            persistAllowed(handle, account) ||
            globalAllowed(handle);
    }

    /**
     * @notice              Checks whether a handle is allowed for decryption.
     * @param handle        Handle.
     * @return isAllowed    Whether the handle is allowed for decryption.
     */
    function isAllowedForDecryption(
        uint256 handle
    ) public view virtual returns (bool) {
        ACLStorage storage $ = _getACLStorage();
        return $.allowedForDecryption[handle];
    }

    /**
     * @notice              Returns `true` if address `a` is allowed to use `c` and `false` otherwise.
     * @param handle        Handle.
     * @param account       Address of the account.
     * @return isAllowed    Whether the account can access the handle.
     */
    function persistAllowed(
        uint256 handle,
        address account
    ) public view virtual returns (bool) {
        ACLStorage storage $ = _getACLStorage();
        return $.persistedAllowedPairs[handle][account];
    }

    /**
     * @notice              Returns `true` if the handle is allowed globally.
     * @param handle        Handle.
     * @return isAllowed    Whether the handle is allowed globally.
     */
    function globalAllowed(uint256 handle) public view virtual returns (bool) {
        ACLStorage storage $ = _getACLStorage();
        return $.globalHandles[handle];
    }

    /**
     * @dev This function removes the transient allowances, which could be useful for integration with
     *      Account Abstraction when bundling several UserOps calling the TaskManagerCoprocessor.
     */
    function cleanTransientStorage() external virtual {
        if (msg.sender != TASK_MANAGER_ADDRESS_) {
            revert DirectAllowForbidden(msg.sender);
        }

        assembly {
            let length := tload(0)
            tstore(0, 0)
            let lengthPlusOne := add(length, 1)
            for {
                let i := 1
            } lt(i, lengthPlusOne) {
                i := add(i, 1)
            } {
                let handle := tload(i)
                tstore(i, 0)
                tstore(handle, 0)
            }
        }
    }

    /**
     * @notice        Getter for the name and version of the contract.
     * @return string Name and the version of the contract.
     */
    function getVersion() external pure virtual returns (string memory) {
        return
            string(
                abi.encodePacked(
                    CONTRACT_NAME,
                    " v",
                    Strings.toString(MAJOR_VERSION),
                    ".",
                    Strings.toString(MINOR_VERSION),
                    ".",
                    Strings.toString(PATCH_VERSION)
                )
            );
    }

    /**
     * @dev                         Returns the ACL storage location.
     */
    function _getACLStorage() internal pure returns (ACLStorage storage $) {
        bytes32 slot = ACL_SLOT;
        assembly {
            $.slot := slot
        }
    }

    function isAllowedWithPermission(
        Permission memory permission,
        uint256 handle
    ) public view withPermission(permission) returns (bool) {
        return isAllowed(handle, permission.issuer);
    }
}
