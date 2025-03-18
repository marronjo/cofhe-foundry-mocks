import { task } from 'hardhat/config'
import { TASK_MANAGER_ADDRESS, ZK_VERIFIER_ADDRESS, QUERY_DECRYPTER_ADDRESS } from './utils'

task('check-mocks-on-anvil', 'Checks if the mocks are deployed on Anvil').setAction(async (taskArgs, hre) => {
	const network = hre.network.name
	if (network !== 'anvil') {
		console.log(`This task is intended to run on the Anvil network. Current network: ${network}`)
		return
	}

	const taskManager = await hre.ethers.getContractAt('TaskManager', TASK_MANAGER_ADDRESS)
	const acl = await hre.ethers.getContractAt('ACL', await taskManager.acl())
	const zkVerifier = await hre.ethers.getContractAt('MockZkVerifier', ZK_VERIFIER_ADDRESS)
	const queryDecrypter = await hre.ethers.getContractAt('MockQueryDecrypter', QUERY_DECRYPTER_ADDRESS)

	console.log('\t! TaskManager exists:', await taskManager.exists())
	console.log('\t! ACL exists:', await acl.exists())
	console.log('\t! ZkVerifier exists:', await zkVerifier.exists())
	console.log('\t! QueryDecrypter exists:', await queryDecrypter.exists())
})
