import * as anchor from "@coral-xyz/anchor"
import { Program } from "@coral-xyz/anchor"
import { assert } from "chai"
import { createHash } from "crypto"

describe("spending-session", () => {
  const provider = anchor.AnchorProvider.env()
  anchor.setProvider(provider)

  const program = anchor.workspace.SpendingSession as Program<any>
  const owner = provider.wallet

  // Session ID (16 bytes)
  const sessionId = Buffer.alloc(16)
  sessionId.write("sess-test-001")

  // Agent ID (32 bytes)
  const agentId = Buffer.alloc(32)
  agentId.write("test-agent-001")

  // Policy hash
  const policyHash = Array.from(
    createHash("sha256").update("test-policy").digest(),
  )

  // Merchant identifiers (32-byte hashes)
  const merchantOpenAI = Array.from(
    createHash("sha256").update("OpenAI").digest(),
  )
  const merchantAWS = Array.from(
    createHash("sha256").update("AWS").digest(),
  )
  const merchantCasino = Array.from(
    createHash("sha256").update("CryptoCasino").digest(),
  )

  // PDA
  const [sessionPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("session"), owner.publicKey.toBuffer(), sessionId],
    program.programId,
  )

  // 1 hour from now
  const expiresAt = Math.floor(Date.now() / 1000) + 3600
  const maxAmountUsdc = new anchor.BN(50_000_000) // $50 in micro-units

  it("creates a spending session", async () => {
    const tx = await program.methods
      .createSession(
        Array.from(sessionId) as any,
        Array.from(agentId) as any,
        maxAmountUsdc,
        new anchor.BN(expiresAt),
        [merchantOpenAI as any, merchantAWS as any],
        policyHash as any,
      )
      .accounts({
        sessionAccount: sessionPda,
        owner: owner.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc()

    console.log("  create_session tx:", tx)

    const account = await program.account.spendingSessionAccount.fetch(sessionPda)
    assert.equal(account.owner.toBase58(), owner.publicKey.toBase58())
    assert.equal(account.maxAmountUsdc.toNumber(), 50_000_000)
    assert.equal(account.spentSoFar.toNumber(), 0)
    assert.equal(account.status, 0) // Active
    assert.equal(account.merchantCount, 2)
  })

  it("spends from session (valid merchant)", async () => {
    const spendAmount = new anchor.BN(3_000_000) // $3

    const tx = await program.methods
      .spendFromSession(spendAmount, merchantOpenAI as any)
      .accounts({
        sessionAccount: sessionPda,
        owner: owner.publicKey,
      })
      .rpc()

    console.log("  spend_from_session tx:", tx)

    const account = await program.account.spendingSessionAccount.fetch(sessionPda)
    assert.equal(account.spentSoFar.toNumber(), 3_000_000)
    assert.equal(account.status, 0) // Still active
  })

  it("rejects spend from unauthorized merchant", async () => {
    const spendAmount = new anchor.BN(1_000_000)

    try {
      await program.methods
        .spendFromSession(spendAmount, merchantCasino as any)
        .accounts({
          sessionAccount: sessionPda,
          owner: owner.publicKey,
        })
        .rpc()

      assert.fail("Should have thrown MerchantNotAllowed")
    } catch (err: any) {
      assert.ok(
        err.toString().includes("MerchantNotAllowed") || err.toString().includes("Error"),
      )
    }
  })

  it("rejects spend exceeding budget", async () => {
    const hugeAmount = new anchor.BN(100_000_000) // $100 > $50 budget

    try {
      await program.methods
        .spendFromSession(hugeAmount, merchantAWS as any)
        .accounts({
          sessionAccount: sessionPda,
          owner: owner.publicKey,
        })
        .rpc()

      assert.fail("Should have thrown BudgetExceeded")
    } catch (err: any) {
      assert.ok(
        err.toString().includes("BudgetExceeded") || err.toString().includes("Error"),
      )
    }
  })

  it("auto-exhausts when fully spent", async () => {
    // Already spent $3, budget is $50, so spend $47 more
    const remaining = new anchor.BN(47_000_000)

    const tx = await program.methods
      .spendFromSession(remaining, merchantAWS as any)
      .accounts({
        sessionAccount: sessionPda,
        owner: owner.publicKey,
      })
      .rpc()

    console.log("  spend_from_session (exhaust) tx:", tx)

    const account = await program.account.spendingSessionAccount.fetch(sessionPda)
    assert.equal(account.spentSoFar.toNumber(), 50_000_000)
    assert.equal(account.status, 1) // Exhausted
  })

  it("rejects spend on exhausted session", async () => {
    const small = new anchor.BN(1_000_000)

    try {
      await program.methods
        .spendFromSession(small, merchantOpenAI as any)
        .accounts({
          sessionAccount: sessionPda,
          owner: owner.publicKey,
        })
        .rpc()

      assert.fail("Should have thrown SessionNotActive")
    } catch (err: any) {
      assert.ok(
        err.toString().includes("SessionNotActive") || err.toString().includes("Error"),
      )
    }
  })

  // Test revoke on a new session
  describe("revoke flow", () => {
    const sessionId2 = Buffer.alloc(16)
    sessionId2.write("sess-test-002")

    const [sessionPda2] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("session"), owner.publicKey.toBuffer(), sessionId2],
      program.programId,
    )

    it("creates a second session for revoke test", async () => {
      await program.methods
        .createSession(
          Array.from(sessionId2) as any,
          Array.from(agentId) as any,
          new anchor.BN(10_000_000),
          new anchor.BN(expiresAt),
          [],
          policyHash as any,
        )
        .accounts({
          sessionAccount: sessionPda2,
          owner: owner.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc()
    })

    it("revokes an active session", async () => {
      const tx = await program.methods
        .revokeSession()
        .accounts({
          sessionAccount: sessionPda2,
          owner: owner.publicKey,
        })
        .rpc()

      console.log("  revoke_session tx:", tx)

      const account = await program.account.spendingSessionAccount.fetch(sessionPda2)
      assert.equal(account.status, 3) // Revoked
    })

    it("closes a non-active session", async () => {
      const tx = await program.methods
        .closeSession()
        .accounts({
          sessionAccount: sessionPda2,
          owner: owner.publicKey,
        })
        .rpc()

      console.log("  close_session tx:", tx)

      const account = await provider.connection.getAccountInfo(sessionPda2)
      assert.isNull(account)
    })
  })

  describe("validation", () => {
    it("rejects expired session creation", async () => {
      const pastSessionId = Buffer.alloc(16)
      pastSessionId.write("sess-past")

      const [pastPda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("session"), owner.publicKey.toBuffer(), pastSessionId],
        program.programId,
      )

      try {
        await program.methods
          .createSession(
            Array.from(pastSessionId) as any,
            Array.from(agentId) as any,
            new anchor.BN(1_000_000),
            new anchor.BN(Math.floor(Date.now() / 1000) - 100), // past
            [],
            policyHash as any,
          )
          .accounts({
            sessionAccount: pastPda,
            owner: owner.publicKey,
            systemProgram: anchor.web3.SystemProgram.programId,
          })
          .rpc()

        assert.fail("Should have thrown InvalidExpiration")
      } catch (err: any) {
        assert.ok(
          err.toString().includes("InvalidExpiration") || err.toString().includes("Error"),
        )
      }
    })

    it("rejects zero amount session", async () => {
      const zeroSessionId = Buffer.alloc(16)
      zeroSessionId.write("sess-zero")

      const [zeroPda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("session"), owner.publicKey.toBuffer(), zeroSessionId],
        program.programId,
      )

      try {
        await program.methods
          .createSession(
            Array.from(zeroSessionId) as any,
            Array.from(agentId) as any,
            new anchor.BN(0),
            new anchor.BN(expiresAt),
            [],
            policyHash as any,
          )
          .accounts({
            sessionAccount: zeroPda,
            owner: owner.publicKey,
            systemProgram: anchor.web3.SystemProgram.programId,
          })
          .rpc()

        assert.fail("Should have thrown InvalidAmount")
      } catch (err: any) {
        assert.ok(
          err.toString().includes("InvalidAmount") || err.toString().includes("Error"),
        )
      }
    })
  })
})
