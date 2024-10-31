const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0xe1D85Aa3449690185371193DD46D60c3DA9FC709";
  const usernamePlain = "username";
  // Data to be set [END]

  const signer = (await ethers.getSigners())[0];
  const accountManager = await ethers.getContractAt("AccountManager", accountManagerAddress, signer);

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), 'hex');

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, 'sha256');

  // Remove email
  const tx = await accountManager.removeEmail(hashedUsername);
  await tx.wait();

  console.log(`Email removed for user "${usernamePlain}" (hashed: ${hashedUsername.toString('hex')})`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error removing email:", error);
    process.exit(1);
  });