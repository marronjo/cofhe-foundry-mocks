import { HardhatUserConfig } from 'hardhat/config'
import '@nomicfoundation/hardhat-toolbox'
import '@nomicfoundation/hardhat-foundry'
import '@nomicfoundation/hardhat-ethers'

import './tasks'

const config: HardhatUserConfig = {
	solidity: {
		version: '0.8.28',
		settings: {
			evmVersion: 'cancun',
		},
	},
	networks: {
		anvil: {
			url: 'http://127.0.0.1:8545',
			chainId: 31337,
			accounts: ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'],
		},
	},
}

export default config
