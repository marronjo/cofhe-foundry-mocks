import { task } from 'hardhat/config'
import { TaskManager, MockZkVerifier, MockQueryDecrypter } from '../typechain-types'
import { execSync } from 'child_process'
import fs from 'fs/promises'
import { anvilSetCode, TASK_MANAGER_ADDRESS, ZK_VERIFIER_ADDRESS, QUERY_DECRYPTER_ADDRESS } from './utils'

task('deploy-mocks-on-anvil', 'Runs a script on the Anvil network').setAction(async (taskArgs, hre) => {
	console.log('Deploy Mocks On Anvil... \n')

	// Get Signer
	const [signer] = await hre.ethers.getSigners()

	const network = hre.network.name
	if (network !== 'anvil') {
		console.log(`This task is intended to run on the Anvil network. Current network: ${network}`)
		return
	}

	await hre.run('compile')
	await execSync('forge compile')

	// Get TaskManager bytecode
	console.log('Deploy TaskManager...')

	const taskManagerBytecode = await fs.readFile('./out/MockTaskManager.sol/TaskManager.json', 'utf8')
	const taskManagerJson = JSON.parse(taskManagerBytecode)
	await anvilSetCode(TASK_MANAGER_ADDRESS, taskManagerJson.deployedBytecode.object)

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
	await anvilSetCode(ZK_VERIFIER_ADDRESS, zkVerifierJson.deployedBytecode.object)
	const zkVerifier: MockZkVerifier = await hre.ethers.getContractAt('MockZkVerifier', ZK_VERIFIER_ADDRESS)

	console.log('\t! MockZkVerifier deployed:', await zkVerifier.getAddress())
	const zkVerifierExists = await zkVerifier.exists()
	console.log('\t! Check zkVerifier Exists', zkVerifierExists)

	// Deploy MockQueryDecrypter
	console.log('Deploy MockQueryDecrypter')

	const queryDecrypterBytecode = await fs.readFile('./out/MockQueryDecrypter.sol/MockQueryDecrypter.json', 'utf8')
	const queryDecrypterJson = JSON.parse(queryDecrypterBytecode)
	await anvilSetCode(QUERY_DECRYPTER_ADDRESS, queryDecrypterJson.deployedBytecode.object)
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
