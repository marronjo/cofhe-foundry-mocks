import { HardhatUserConfig, task } from 'hardhat/config'
import '@nomicfoundation/hardhat-toolbox'
import '@nomicfoundation/hardhat-foundry'
import '@nomicfoundation/hardhat-ethers'

import axios from 'axios'
import { execSync } from 'child_process'
import fs from 'fs/promises'
import { MockQueryDecrypter, mockTaskManagerSol, MockZkVerifier } from './typechain-types/src'
import { TaskManager } from './typechain-types'

const TASK_MANAGER_ADDRESS = '0xbeb4eF1fcEa618C6ca38e3828B00f8D481EC2CC2'
const ZK_VERIFIER_ADDRESS = '0x0000000000000000000000000000000000000100'
const QUERY_DECRYPTER_ADDRESS = '0x0000000000000000000000000000000000000200'

// Define a custom task
task('deploy-mocks-on-anvil', 'Runs a script on the Anvil network').setAction(async (taskArgs, hre) => {
	console.log('Deploy Mocks On Anvil... \n')

	// Get Signer
	const [signer] = await hre.ethers.getSigners()
	console.log({ signer })

	const network = hre.network.name
	if (network !== 'anvil') {
		console.log(`This task is intended to run on the Anvil network. Current network: ${network}`)
		return
	}

	await hre.run('compile')

	// // Deploy MockTaskManager (using ethers)
	// const MockTaskManager = await hre.ethers.getContractFactory('MockTaskManager')
	// const mockTaskManager = await MockTaskManager.deploy(TASK_MANAGER_ADDRESS, 0, 1)
	// console.log({ mockTaskManagerAddress: mockTaskManager.address })

	// Get TaskManager bytecode
	console.log('Deploy TaskManager...')

	const taskManagerBytecode = await fs.readFile('./out/MockTaskManager.sol/TaskManager.json', 'utf8')
	const taskManagerJson = JSON.parse(taskManagerBytecode)
	await axios.post('http://127.0.0.1:8545', {
		jsonrpc: '2.0',
		method: 'anvil_setCode',
		params: [TASK_MANAGER_ADDRESS, taskManagerJson.deployedBytecode.object],
		id: 1,
	})
	const taskManager: TaskManager = await hre.ethers.getContractAt('TaskManager', TASK_MANAGER_ADDRESS)
	const tmDeployTx = await taskManager.initialize(signer.address, 0, 1)
	await tmDeployTx.wait()

	console.log('\t! Task Manager deployed:', await taskManager.getAddress())

	// Deploy Proxy, ACL and Initialize ACL
	console.log('Deploy Proxy, ACL and Initialize ACL')
	// Deploy ACL implementation
	const ACL = await hre.ethers.getContractFactory('ACL')
	const aclImplementation = await ACL.deploy()
	await aclImplementation.waitForDeployment()
	console.log('\t! ACL Implementation deployed:', await aclImplementation.getAddress())

	// Encode initialization data
	const initData = aclImplementation.interface.encodeFunctionData('initialize', [signer.address])

	// Deploy ERC1967 Proxy
	const ERC1967Proxy = await hre.ethers.getContractFactory('ERC1967Proxy')
	const proxy = await ERC1967Proxy.deploy(await aclImplementation.getAddress(), initData)
	await proxy.waitForDeployment()
	console.log('\t! ERC1967 Proxy deployed:', await proxy.getAddress())

	// Get ACL instance at proxy address
	const acl = ACL.attach(await proxy.getAddress())
	console.log('\t! ACL Proxy deployed:', await acl.getAddress())

	// Set ACL in TaskManager
	const setAclTx = await taskManager.setACLContract(await acl.getAddress())
	await setAclTx.wait()
	console.log('\t! ACL set in TaskManager')

	// Deploy MockZkVerifier
	console.log('Deploy MockZkVerifier')

	const zkVerifierBytecode = await fs.readFile('./out/MockZkVerifier.sol/MockZkVerifier.json', 'utf8')
	const zkVerifierJson = JSON.parse(zkVerifierBytecode)
	await axios.post('http://127.0.0.1:8545', {
		jsonrpc: '2.0',
		method: 'anvil_setCode',
		params: [ZK_VERIFIER_ADDRESS, zkVerifierJson.deployedBytecode.object],
		id: 1,
	})
	const zkVerifier: MockZkVerifier = await hre.ethers.getContractAt('MockZkVerifier', ZK_VERIFIER_ADDRESS)

	console.log('\t! MockZkVerifier deployed:', await zkVerifier.getAddress())
	const zkVerifierExists = await zkVerifier.exists()
	console.log('\t! Check zkVerifier Exists', zkVerifierExists)

	// Deploy MockQueryDecrypter
	console.log('Deploy MockQueryDecrypter')

	const queryDecrypterBytecode = await fs.readFile('./out/MockQueryDecrypter.sol/MockQueryDecrypter.json', 'utf8')
	const queryDecrypterJson = JSON.parse(queryDecrypterBytecode)
	await axios.post('http://127.0.0.1:8545', {
		jsonrpc: '2.0',
		method: 'anvil_setCode',
		params: [QUERY_DECRYPTER_ADDRESS, queryDecrypterJson.deployedBytecode.object],
		id: 1,
	})
	const queryDecrypter: MockQueryDecrypter = await hre.ethers.getContractAt('MockQueryDecrypter', QUERY_DECRYPTER_ADDRESS)

	console.log('\t! MockQueryDecrypter deployed:', await queryDecrypter.getAddress())
	const queryDecrypterExists = await queryDecrypter.exists()
	console.log('\t! Check queryDecrypter Exists', queryDecrypterExists)

	// Initialize MockQueryDecrypter
	const initTx = await queryDecrypter.initialize(TASK_MANAGER_ADDRESS, await acl.getAddress())
	await initTx.wait()
	console.log('\t! MockQueryDecrypter initialized')

	console.log('\t! MockQueryDecrypter TaskManager address:', await queryDecrypter.taskManager())
	console.log('\t! MockQueryDecrypter ACL address:', await queryDecrypter.acl())
})

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
