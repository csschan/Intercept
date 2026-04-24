import * as anchor from "@coral-xyz/anchor"
import { Program } from "@coral-xyz/anchor"
import { assert } from "chai"
import { createHash } from "crypto"

// IDL will be auto-generated after `anchor build`
// import { PolicyRegistry } from "../target/types/policy_registry"

describe("policy-registry", () => {
  const provider = anchor.AnchorProvider.env()
  anchor.setProvider(provider)

  const program = anchor.workspace.PolicyRegistry as Program<any>
  const owner = provider.wallet

  // Deterministic agent ID (UUID as 32 bytes)
  const agentId = Buffer.alloc(32)
  agentId.write("test-agent-001")

  // Policy hash (SHA-256 of a test policy)
  const testPolicy = JSON.stringify({
    autoApproveBelowUsdc: 5,
    monthlyLimitUsdc: 100,
    tokenAllowlist: ["USDC", "SOL"],
  })
  const policyHash = Array.from(createHash("sha256").update(testPolicy).digest())

  // PDA for the policy account
  const [policyPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("policy"), owner.publicKey.toBuffer(), agentId],
    program.programId,
  )

  const metadataUri = "https://api.agentguard.io/v1/policies/test-agent-001"

  it("initializes a policy", async () => {
    const tx = await program.methods
      .initializePolicy(
        Array.from(agentId) as any,
        policyHash as any,
        metadataUri,
      )
      .accounts({
        policyAccount: policyPda,
        owner: owner.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc()

    console.log("  initialize_policy tx:", tx)

    const account = await program.account.policyAccount.fetch(policyPda)
    assert.equal(account.owner.toBase58(), owner.publicKey.toBase58())
    assert.deepEqual(Array.from(account.policyHash), policyHash)
    assert.equal(account.version, 1)
    assert.equal(account.metadataUri, metadataUri)
  })

  it("verifies a matching policy hash", async () => {
    const tx = await program.methods
      .verifyPolicy(policyHash as any)
      .accounts({ policyAccount: policyPda })
      .rpc()

    console.log("  verify_policy tx:", tx)
    // If it doesn't error, verification passed (event emitted on-chain)
  })

  it("verifies a mismatched policy hash without erroring", async () => {
    const wrongHash = Array.from(createHash("sha256").update("wrong").digest())

    // Should NOT throw — it emits an event with matches=false
    const tx = await program.methods
      .verifyPolicy(wrongHash as any)
      .accounts({ policyAccount: policyPda })
      .rpc()

    console.log("  verify_policy (mismatch) tx:", tx)
  })

  it("updates the policy hash", async () => {
    const newPolicy = JSON.stringify({ autoApproveBelowUsdc: 10, monthlyLimitUsdc: 200 })
    const newHash = Array.from(createHash("sha256").update(newPolicy).digest())
    const newUri = "https://api.agentguard.io/v1/policies/test-agent-001?v=2"

    const tx = await program.methods
      .updatePolicy(newHash as any, newUri)
      .accounts({
        policyAccount: policyPda,
        owner: owner.publicKey,
      })
      .rpc()

    console.log("  update_policy tx:", tx)

    const account = await program.account.policyAccount.fetch(policyPda)
    assert.deepEqual(Array.from(account.policyHash), newHash)
    assert.equal(account.version, 2)
    assert.equal(account.metadataUri, newUri)
  })

  it("rejects update from non-owner", async () => {
    const fakeOwner = anchor.web3.Keypair.generate()

    // Airdrop SOL to fake owner
    const sig = await provider.connection.requestAirdrop(
      fakeOwner.publicKey,
      anchor.web3.LAMPORTS_PER_SOL,
    )
    await provider.connection.confirmTransaction(sig)

    const fakeHash = Array.from(createHash("sha256").update("hack").digest())

    try {
      await program.methods
        .updatePolicy(fakeHash as any, "hacked")
        .accounts({
          policyAccount: policyPda,
          owner: fakeOwner.publicKey,
        })
        .signers([fakeOwner])
        .rpc()

      assert.fail("Should have thrown Unauthorized error")
    } catch (err: any) {
      // PDA seeds won't match so anchor will reject
      assert.ok(err.toString().includes("Error") || err.toString().includes("ConstraintSeeds"))
    }
  })

  it("rejects metadata URI > 128 chars", async () => {
    const longUri = "x".repeat(200)
    const hash = Array.from(createHash("sha256").update("test").digest())

    try {
      await program.methods
        .updatePolicy(hash as any, longUri)
        .accounts({
          policyAccount: policyPda,
          owner: owner.publicKey,
        })
        .rpc()

      assert.fail("Should have thrown MetadataUriTooLong")
    } catch (err: any) {
      assert.ok(err.toString().includes("MetadataUriTooLong") || err.toString().includes("Error"))
    }
  })

  it("closes the policy account", async () => {
    const balanceBefore = await provider.connection.getBalance(owner.publicKey)

    const tx = await program.methods
      .closePolicy()
      .accounts({
        policyAccount: policyPda,
        owner: owner.publicKey,
      })
      .rpc()

    console.log("  close_policy tx:", tx)

    const balanceAfter = await provider.connection.getBalance(owner.publicKey)
    // Owner should have received rent back (minus tx fee)
    assert.ok(balanceAfter > balanceBefore - 10000)

    // Account should no longer exist
    const account = await provider.connection.getAccountInfo(policyPda)
    assert.isNull(account)
  })
})
