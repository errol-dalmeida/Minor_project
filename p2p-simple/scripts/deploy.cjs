const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

async function main() {
  const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
  console.log(`\n🚀 Connecting to Ethereum node at ${rpcUrl}...`);

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const accounts = await provider.listAccounts();
  if (accounts.length === 0) {
    throw new Error("No accounts found on JSON-RPC node. Ensure Hardhat node is running.");
  }

  const deployer = await provider.getSigner(accounts[0].address);
  const deployerAddress = await deployer.getAddress();
  console.log(`👤 Deployer account: ${deployerAddress}`);

  const artifactPath = path.join(__dirname, "../artifacts/contracts/IdentityRegistry.sol/IdentityRegistry.json");
  if (!fs.existsSync(artifactPath)) {
    throw new Error("Artifact not found. Run 'npx hardhat --config hardhat.config.cjs compile' first.");
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, deployer);

  console.log("⏳ Deploying IdentityRegistry contract...");
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log(`✅ IdentityRegistry successfully deployed at: ${contractAddress}`);

  const deploymentData = {
    address: contractAddress,
    network: "localhost",
    rpcUrl: rpcUrl,
    chainId: 31337,
    abi: artifact.abi,
    deployedAt: new Date().toISOString()
  };

  const outputPath = path.join(__dirname, "../contracts/deployedRegistry.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentData, null, 2));
  console.log(`📄 Saved deployment details to: contracts/deployedRegistry.json\n`);
}

main().catch((err) => {
  console.error("❌ Deployment error:", err.message);
  process.exitCode = 1;
});
