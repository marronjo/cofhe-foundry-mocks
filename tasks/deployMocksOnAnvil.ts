import { task } from 'hardhat/config'
import { MockZkVerifier, MockQueryDecrypter, TaskManager, ACL, Example } from '../typechain-types'
import { execSync } from 'child_process'
import fs from 'fs/promises'
import { anvilSetCode, TASK_MANAGER_ADDRESS, ZK_VERIFIER_ADDRESS, QUERY_DECRYPTER_ADDRESS, EXAMPLE_FHE_COUNTER_ADDRESS } from './utils'
import { HardhatRuntimeEnvironment } from 'hardhat/types'

const deployMockTaskManager = async (hre: HardhatRuntimeEnvironment) => {
	const [signer] = await hre.ethers.getSigners()

	console.log('Task Manager')

	// Deploy MockTaskManager
	const tmBytecode = await fs.readFile('./out/MockTaskManager.sol/TaskManager.json', 'utf8')
	const tmJson = JSON.parse(tmBytecode)
	await anvilSetCode(TASK_MANAGER_ADDRESS, tmJson.deployedBytecode.object)
	const taskManager: TaskManager = await hre.ethers.getContractAt('TaskManager', TASK_MANAGER_ADDRESS)
	console.log('  - deployed')

	// Initialize MockTaskManager
	const initTx = await taskManager.initialize(signer.address)
	await initTx.wait()
	console.log('  - initialized')

	const tmExists = await taskManager.exists()
	console.log('  - exists', tmExists ? 'yes' : 'no')

	console.log('  - address:', await taskManager.getAddress())

	return taskManager
}

const deployMockACL = async (hre: HardhatRuntimeEnvironment) => {
	// Get Signer
	const [signer] = await hre.ethers.getSigners()

	console.log('ACL')

	// Deploy ACL implementation
	const aclFactory = await hre.ethers.getContractFactory('ACL')
	const aclImplementation = await aclFactory.deploy()
	await aclImplementation.waitForDeployment()
	console.log('  - implementation deployed')

	// Encode initialization data
	const aclInitData = aclImplementation.interface.encodeFunctionData('initialize', [signer.address])

	// Deploy ERC1967 Proxy
	const ERC1967Proxy = await hre.ethers.getContractFactory('ERC1967Proxy')
	const proxy = await ERC1967Proxy.deploy(await aclImplementation.getAddress(), aclInitData)
	await proxy.waitForDeployment()
	console.log('  - proxy deployed')

	// Get ACL instance at proxy address
	const acl: ACL = await hre.ethers.getContractAt('ACL', await proxy.getAddress())
	console.log('  - address:', await acl.getAddress())

	return acl
}

const deployMockZkVerifier = async (hre: HardhatRuntimeEnvironment) => {
	console.log('ZkVerifier')

	const zkVerifierBytecode = await fs.readFile('./out/MockZkVerifier.sol/MockZkVerifier.json', 'utf8')
	const zkVerifierJson = JSON.parse(zkVerifierBytecode)
	await anvilSetCode(ZK_VERIFIER_ADDRESS, zkVerifierJson.deployedBytecode.object)
	const zkVerifier: MockZkVerifier = await hre.ethers.getContractAt('MockZkVerifier', ZK_VERIFIER_ADDRESS)
	console.log('  - deployed')

	const zkVerifierExists = await zkVerifier.exists()
	console.log('  - exists', zkVerifierExists ? 'yes' : 'no')

	console.log('  - address:', await zkVerifier.getAddress())

	return zkVerifier
}

const deployMockQueryDecrypter = async (hre: HardhatRuntimeEnvironment, acl: ACL) => {
	console.log('QueryDecrypter')

	const queryDecrypterBytecode = await fs.readFile('./out/MockQueryDecrypter.sol/MockQueryDecrypter.json', 'utf8')
	const queryDecrypterJson = JSON.parse(queryDecrypterBytecode)
	await anvilSetCode(QUERY_DECRYPTER_ADDRESS, queryDecrypterJson.deployedBytecode.object)
	const queryDecrypter: MockQueryDecrypter = await hre.ethers.getContractAt('MockQueryDecrypter', QUERY_DECRYPTER_ADDRESS)
	console.log('  - deployed')

	const queryDecrypterExists = await queryDecrypter.exists()
	console.log('  - exists', queryDecrypterExists ? 'yes' : 'no')

	// Initialize MockQueryDecrypter
	const initTx = await queryDecrypter.initialize(TASK_MANAGER_ADDRESS, await acl.getAddress())
	await initTx.wait()
	console.log('  - initialized')

	console.log('  - address:', await queryDecrypter.getAddress())

	return queryDecrypter
}

const deployExampleFHECounter = async (hre: HardhatRuntimeEnvironment) => {
	console.log('ExampleFHECounter')

	const exampleBytecode = await fs.readFile('./out/Example.sol/Example.json', 'utf8')
	const exampleJson = JSON.parse(exampleBytecode)
	await anvilSetCode(EXAMPLE_FHE_COUNTER_ADDRESS, exampleJson.deployedBytecode.object)
	const example: Example = await hre.ethers.getContractAt('Example', EXAMPLE_FHE_COUNTER_ADDRESS)
	console.log('  - deployed')

	console.log('  - address:', await example.getAddress())

	return example
}

const setTaskManagerACL = async (taskManager: TaskManager, acl: ACL) => {
	const setAclTx = await taskManager.setACLContract(await acl.getAddress())
	await setAclTx.wait()
	console.log('TaskManager ACL set')
}

task('deploy-mocks-on-anvil', 'Runs a script on the Anvil network').setAction(async (taskArgs, hre) => {
	console.log('Deploy Mocks On Anvil... \n')

	const network = hre.network.name
	if (network !== 'anvil') {
		console.log(`This task is intended to run on the Anvil network. Current network: ${network}`)
		return
	}

	await hre.run('compile')
	await execSync('forge compile')

	const taskManager = await deployMockTaskManager(hre)
	const acl = await deployMockACL(hre)

	console.log('Task Manager Exists', await taskManager.getAddress(), await taskManager.exists())
	await setTaskManagerACL(taskManager, acl)
	const zkVerifier = await deployMockZkVerifier(hre)
	const queryDecrypter = await deployMockQueryDecrypter(hre, acl)

	const example = await deployExampleFHECounter(hre)
	const [sender, backup, bob] = await hre.ethers.getSigners()
	console.log('Bob Address', await bob.getAddress())
	await example.connect(bob).setNumberTrivial(10)

	const numberHash = await example.numberHash()
	console.log('Number Hash', numberHash)

	console.log('Done!')
})
