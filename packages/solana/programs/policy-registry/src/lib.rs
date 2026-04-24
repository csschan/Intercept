use anchor_lang::prelude::*;

declare_id!("FKvRpAWkPHh6HqQkvSfABAkrMrhaJz195q5Rw2NvznGG");

/// Agent Guard — On-chain Policy Registry
///
/// Stores a SHA-256 hash of each agent's spending policy on-chain.
/// This allows anyone to verify that an agent's spending is governed
/// by a policy, and that the policy hasn't been tampered with.
///
/// The actual policy rules live off-chain (in PostgreSQL) for performance.
/// The hash serves as a tamper-evident commitment to those rules.
#[program]
pub mod policy_registry {
    use super::*;

    /// Register a new policy for an agent.
    /// Creates a PolicyAccount PDA derived from [owner, agent_id].
    pub fn initialize_policy(
        ctx: Context<InitializePolicy>,
        agent_id: [u8; 32],
        policy_hash: [u8; 32],
        metadata_uri: String,
    ) -> Result<()> {
        require!(metadata_uri.len() <= 128, PolicyError::MetadataUriTooLong);

        let account = &mut ctx.accounts.policy_account;
        account.owner = ctx.accounts.owner.key();
        account.agent_id = agent_id;
        account.policy_hash = policy_hash;
        account.metadata_uri = metadata_uri;
        account.version = 1;
        account.updated_at = Clock::get()?.unix_timestamp;
        account.bump = ctx.bumps.policy_account;

        emit!(PolicyInitialized {
            owner: ctx.accounts.owner.key(),
            agent_id,
            policy_hash,
            version: 1,
            timestamp: account.updated_at,
        });

        Ok(())
    }

    /// Update the policy hash for an existing agent.
    /// Only the original owner can update.
    pub fn update_policy(
        ctx: Context<UpdatePolicy>,
        new_hash: [u8; 32],
        metadata_uri: String,
    ) -> Result<()> {
        require!(metadata_uri.len() <= 128, PolicyError::MetadataUriTooLong);

        let account = &mut ctx.accounts.policy_account;
        let old_hash = account.policy_hash;

        account.policy_hash = new_hash;
        account.metadata_uri = metadata_uri;
        account.version += 1;
        account.updated_at = Clock::get()?.unix_timestamp;

        emit!(PolicyUpdated {
            owner: ctx.accounts.owner.key(),
            agent_id: account.agent_id,
            old_hash,
            new_hash,
            version: account.version,
            timestamp: account.updated_at,
        });

        Ok(())
    }

    /// Verify a policy hash on-chain.
    /// Returns an event confirming whether the provided hash matches
    /// what's stored for this agent. Useful for merchant verification.
    pub fn verify_policy(
        ctx: Context<VerifyPolicy>,
        claimed_hash: [u8; 32],
    ) -> Result<()> {
        let account = &ctx.accounts.policy_account;
        let matches = account.policy_hash == claimed_hash;

        emit!(PolicyVerified {
            owner: account.owner,
            agent_id: account.agent_id,
            claimed_hash,
            stored_hash: account.policy_hash,
            matches,
            version: account.version,
            timestamp: Clock::get()?.unix_timestamp,
        });

        // We don't error on mismatch — we emit the result so callers
        // can react. This allows read-only verification without failing tx.
        Ok(())
    }

    /// Close the policy account and reclaim rent.
    /// Only the owner can close their agent's policy account.
    pub fn close_policy(
        _ctx: Context<ClosePolicy>,
    ) -> Result<()> {
        // Anchor handles the rent reclamation via `close = owner` constraint
        Ok(())
    }
}

// ── Accounts ──────────────────────────────────────────────────────────────────

#[account]
#[derive(Default)]
pub struct PolicyAccount {
    /// The wallet that owns this agent's policy
    pub owner: Pubkey,              // 32
    /// Unique identifier for the agent (UUID as bytes)
    pub agent_id: [u8; 32],         // 32
    /// SHA-256 hash of the JSON policy document stored off-chain
    pub policy_hash: [u8; 32],      // 32
    /// URI pointing to the off-chain policy (e.g. ipfs:// or https://)
    pub metadata_uri: String,       // 4 + 128 max
    /// Policy version — increments on each update
    pub version: u32,               // 4
    /// Unix timestamp of last update
    pub updated_at: i64,            // 8
    /// PDA bump seed
    pub bump: u8,                   // 1
}

impl PolicyAccount {
    /// Account size: discriminator(8) + owner(32) + agent_id(32) +
    /// policy_hash(32) + metadata_uri(4+128) + version(4) + updated_at(8) + bump(1)
    pub const LEN: usize = 8 + 32 + 32 + 32 + (4 + 128) + 4 + 8 + 1;
}

// ── Contexts ──────────────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(agent_id: [u8; 32])]
pub struct InitializePolicy<'info> {
    #[account(
        init,
        payer = owner,
        space = PolicyAccount::LEN,
        seeds = [b"policy", owner.key().as_ref(), &agent_id],
        bump,
    )]
    pub policy_account: Account<'info, PolicyAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdatePolicy<'info> {
    #[account(
        mut,
        seeds = [b"policy", owner.key().as_ref(), &policy_account.agent_id],
        bump = policy_account.bump,
        has_one = owner @ PolicyError::Unauthorized,
    )]
    pub policy_account: Account<'info, PolicyAccount>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct VerifyPolicy<'info> {
    #[account(
        seeds = [b"policy", policy_account.owner.as_ref(), &policy_account.agent_id],
        bump = policy_account.bump,
    )]
    pub policy_account: Account<'info, PolicyAccount>,
}

#[derive(Accounts)]
pub struct ClosePolicy<'info> {
    #[account(
        mut,
        seeds = [b"policy", owner.key().as_ref(), &policy_account.agent_id],
        bump = policy_account.bump,
        has_one = owner @ PolicyError::Unauthorized,
        close = owner,
    )]
    pub policy_account: Account<'info, PolicyAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

// ── Events ────────────────────────────────────────────────────────────────────

#[event]
pub struct PolicyInitialized {
    pub owner: Pubkey,
    pub agent_id: [u8; 32],
    pub policy_hash: [u8; 32],
    pub version: u32,
    pub timestamp: i64,
}

#[event]
pub struct PolicyUpdated {
    pub owner: Pubkey,
    pub agent_id: [u8; 32],
    pub old_hash: [u8; 32],
    pub new_hash: [u8; 32],
    pub version: u32,
    pub timestamp: i64,
}

#[event]
pub struct PolicyVerified {
    pub owner: Pubkey,
    pub agent_id: [u8; 32],
    pub claimed_hash: [u8; 32],
    pub stored_hash: [u8; 32],
    pub matches: bool,
    pub version: u32,
    pub timestamp: i64,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[error_code]
pub enum PolicyError {
    #[msg("Only the policy owner can perform this action")]
    Unauthorized,
    #[msg("Metadata URI must be 128 characters or less")]
    MetadataUriTooLong,
}
