#!/bin/bash

set -e  # Exit if any command fails

export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

# Admin account
ADMIN=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# Admin private key
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Anvil RPC URL
RPC_URL="http://127.0.0.1:8545"

# Start Anvil (no forking) in the background
echo "Starting Anvil..."
anvil > anvil.log 2>&1 &
ANVIL_PID=$!

# Wait for Anvil to start
sleep 3

# Function to deploy a contract
deploy_contract() {
    local CONTRACT_JSON=$1
    local TARGET_ADDRESS=$2
    local CONSTRUCTOR_ARGS=$3  # Optional constructor args

    echo "Extracting bytecode for $1..."
    forge build
    forge build > /dev/null 2>&1
    BYTECODE=$(jq -r '.deployedBytecode.object' "$CONTRACT_JSON")

    if [ -z "$BYTECODE" ] || [ "$BYTECODE" == "null" ]; then
        echo "❌ Failed to extract bytecode for $1. Make sure the contract is compiled."
        kill $ANVIL_PID
        exit 1
    fi

    # If constructor args exist, append them
    if [ -n "$CONSTRUCTOR_ARGS" ]; then
        echo "Encoding constructor arguments for $1..."
        ENCODED_ARGS=$(cast abi-encode "constructor(address,uint256,uint256)" $CONSTRUCTOR_ARGS)
        BYTECODE="${BYTECODE}${ENCODED_ARGS:2}"
    fi

    echo "Deploying $1 to $TARGET_ADDRESS..."
    cast rpc anvil_setCode "$TARGET_ADDRESS" "$BYTECODE" --rpc-url "$RPC_URL"

    # Verify deployment
    DEPLOYED_CODE=$(cast code "$TARGET_ADDRESS" --rpc-url "$RPC_URL")

    if [ "$DEPLOYED_CODE" = "0x" ]; then
        echo "❌ Deployment failed for $1 at $TARGET_ADDRESS."
    else
        echo "✅ $1 deployed successfully at $TARGET_ADDRESS!"
    fi
}

# Deploy contracts
deploy_contract "out/MockTaskManager.sol/TaskManager.json" "0xbeb4eF1fcEa618C6ca38e3828B00f8D481EC2CC2" "$ADMIN 0 1"
deploy_contract "out/MockZkVerifier.sol/MockZkVerifier.json" "0x0000000000000000000000000000000000000100"
deploy_contract "out/MockQueryDecrypter.sol/MockQueryDecrypter.json" "0x0000000000000000000000000000000000000200"
deploy_contract "out/ACL.sol/ACL.json" "0x0000000000000000000000000000000000000300"

echo "Initializing ACL..."
cast send 0x0000000000000000000000000000000000000300 "initialize(address)" "$ADMIN" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"

echo "Setting ACL contract in TaskManager..."
cast send 0xbeb4eF1fcEa618C6ca38e3828B00f8D481EC2CC2 "setACLContract(address)" "0x0000000000000000000000000000000000000300" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"

# Keep Anvil running or stop it
echo "Press Ctrl+C to stop Anvil."
wait $ANVIL_PID
