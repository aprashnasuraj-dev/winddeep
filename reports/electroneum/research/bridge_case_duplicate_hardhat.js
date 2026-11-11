// Certified ETNBridge source is checked out by the accompanying workflow.
// Offline Hardhat only: all transactions are signed on a disposable local chain.
const { expect } = require("chai");
const { ethers, upgrades } = require("hardhat");

describe("ETNBridge: duplicate logical legacy transaction under case variants", function () {
  async function deploy() {
    const [owner, recipient, outsider] = await ethers.getSigners();
    const Bridge = await ethers.getContractFactory("ETNBridge");
    const bridge = await upgrades.deployProxy(Bridge, [], { kind: "uups" });
    await bridge.waitForDeployment();
    await (await owner.sendTransaction({ to: await bridge.getAddress(), value: ethers.parseEther("10") })).wait();
    return {bridge, owner, recipient, outsider};
  }

  it("accepts second payout for same 32-byte hash using uppercase, while preserving owner-only and identical-spelling controls", async function () {
    const {bridge, recipient, outsider} = await deploy();
    const legacyAddress = "e".repeat(98); // Contract validates length, not legacy checksum.
    const lower = "a".repeat(64), upper = "A".repeat(64);
    expect(Buffer.from(lower, "hex").equals(Buffer.from(upper, "hex"))).to.equal(true);
    const amount = ethers.parseEther("1");
    const before = await ethers.provider.getBalance(recipient.address);

    await (await bridge.crosschainTransfer(recipient.address, legacyAddress, amount, lower, true)).wait();
    await expect(bridge.crosschainTransfer(recipient.address, legacyAddress, amount, lower, true))
      .to.be.revertedWith("Duplicate crosschain transaction");
    await expect(bridge.connect(outsider).crosschainTransfer(recipient.address, legacyAddress, amount, upper, true))
      .to.be.revertedWith("Ownable: caller is not the owner");
    const afterFirst = await ethers.provider.getBalance(recipient.address);
    expect(afterFirst - before).to.equal(amount);

    // This is a second OWNER-authorized call, NOT an unauthorized withdrawal.
    await (await bridge.crosschainTransfer(recipient.address, legacyAddress, amount, upper, true)).wait();
    const afterSecond = await ethers.provider.getBalance(recipient.address);
    const paid = afterSecond - before;
    expect(paid).to.equal(amount * 2n);
    expect(await bridge.getTxAmount(lower)).to.equal(amount);
    expect(await bridge.getTxAmount(upper)).to.equal(amount);
    expect(await bridge.getTotalTxCount()).to.equal(2n);
    expect(await bridge.getTotalCrosschainAmount()).to.equal(amount * 2n);
    expect((await bridge.getTxHistory(recipient.address)).length).to.equal(2);

    console.log("BRIDGE_HASH_CANONICAL_EQUIVALENCE true");
    console.log("BRIDGE_OWNER_ONLY_REJECTS_OUTSIDER true");
    console.log("BRIDGE_IDENTICAL_REPLAY_REJECTED true");
    console.log("BRIDGE_DISTINCT_CASE_DUPLICATE_PAYOUT_2X true");
    console.log("BRIDGE_PAYOUT_WEI", paid.toString());
  });
  it("pausing prevents the owner from executing a second transaction", async function () {
    const {bridge, recipient} = await deploy();
    await (await bridge.pause()).wait();
    await expect(bridge.crosschainTransfer(recipient.address, "e".repeat(98), ethers.parseEther("1"), "a".repeat(64), true))
      .to.be.revertedWith("Pausable: paused");
    console.log("BRIDGE_PAUSE_BLOCKS_TRANSFER true");
  });
});
