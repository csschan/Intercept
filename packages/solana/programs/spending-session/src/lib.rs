use anchor_lang::prelude::*;

declare_id!("DmBoKbEr7rcdcdCEFq94w2rfF6EtSthxqhSM25uCnFDG");

/// Agent Guard — On-chain Spending Session Authority
///
/// Manages time-bound, budget-capped spending sessions for AI agents.
/// Instead of agents holding long-lived wallet keys, the owner creates
/// a scoped session that enforces constraints at the protocol level.
///
/// Flow:
///   1. Owner creates a session (budget, duration, allowed merchants)
///   2. Agent spends within session constraints (no per-tx auth needed)
///   3. Session auto-expires or owner revokes it
///   4. Full audit trail on-chain
#[program]
pub mod spending_session {
    use super::*;

    /// Create a new spending session for an agent.
    /// Only the owner wallet can create sessions.
    pub fn create_session(
        ctx: Context<CreateSession>,
        session_id: [u8; 16],
        agent_id: [u8; 32],
        max_amount_usdc: u64,
        expires_at: i64,
        allowed_merchants: Vec<[u8; 32]>,
        policy_hash: [u8; 32],
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(expires_at > now, SessionError::InvalidExpiration);
        require!(max_amount_usdc > 0, SessionError::InvalidAmount);
        require!(allowed_merchants.len() <= 10, SessionError::TooManyMerchants);

        let account = &mut ctx.accounts.session_account;
        account.owner = ctx.accounts.owner.key();
        account.agent_id = agent_id;
        account.session_id = session_id;
        account.max_amount_usdc = max_amount_usdc;
        account.spent_so_far = 0;
        account.expires_at = expires_at;

        // Copy merchants into fixed array
        let mut merchants = [[0u8; 32]; 10];
        for (i, m) in allowed_merchants.iter().enumerate() {
            merchants[i] = *m;
        }
        account.allowed_merchants = merchants;
        account.merchant_count = allowed_merchants.len() as u8;

        account.status = SessionStatus::Active as u8;
        account.policy_hash = policy_hash;
        account.created_at = now;
        account.bump = ctx.bumps.session_account;

        emit!(SessionCreated {
            owner: ctx.accounts.owner.key(),
            session_id,
            agent_id,
            max_amount_usdc,
            expires_at,
            timestamp: now,
        });

        Ok(())
    }

    /// Spend from an active session.
    /// The owner wallet must sign (agent calls via API which co-signs).
    pub fn spend_from_session(
        ctx: Context<SpendFromSession>,
        amount_usdc: u64,
        merchant: [u8; 32],
    ) -> Result<()> {
        let session = &mut ctx.accounts.session_account;
        let now = Clock::get()?.unix_timestamp;

        // Check session is active
        require!(session.status == SessionStatus::Active as u8, SessionError::SessionNotActive);

        // Check not expired
        if now >= session.expires_at {
            session.status = SessionStatus::Expired as u8;
            return err!(SessionError::SessionExpired);
        }

        // Check budget
        let new_total = session.spent_so_far
            .checked_add(amount_usdc)
            .ok_or(SessionError::BudgetExceeded)?;
        require!(new_total <= session.max_amount_usdc, SessionError::BudgetExceeded);

        // Check merchant allowlist (if non-empty)
        if session.merchant_count > 0 {
            let zero = [0u8; 32];
            let mut found = false;
            for i in 0..session.merchant_count as usize {
                if session.allowed_merchants[i] != zero && session.allowed_merchants[i] == merchant {
                    found = true;
                    break;
                }
            }
            require!(found, SessionError::MerchantNotAllowed);
        }

        // Update spent
        session.spent_so_far = new_total;

        // Auto-exhaust if fully spent
        if session.spent_so_far >= session.max_amount_usdc {
            session.status = SessionStatus::Exhausted as u8;
            emit!(SessionExhausted {
                owner: session.owner,
                session_id: session.session_id,
                total_spent: session.spent_so_far,
                timestamp: now,
            });
        }

        emit!(SessionSpent {
            owner: session.owner,
            session_id: session.session_id,
            amount_usdc,
            new_total: session.spent_so_far,
            remaining: session.max_amount_usdc.saturating_sub(session.spent_so_far),
            merchant,
            timestamp: now,
        });

        Ok(())
    }

    /// Revoke a session. Only the owner can revoke.
    pub fn revoke_session(ctx: Context<RevokeSession>) -> Result<()> {
        let session = &mut ctx.accounts.session_account;
        require!(session.status == SessionStatus::Active as u8, SessionError::SessionNotActive);

        session.status = SessionStatus::Revoked as u8;

        emit!(SessionRevoked {
            owner: session.owner,
            session_id: session.session_id,
            spent_so_far: session.spent_so_far,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Close the session account and reclaim rent.
    /// Only allowed if session is not active.
    pub fn close_session(_ctx: Context<CloseSession>) -> Result<()> {
        // Anchor handles rent reclamation via `close = owner`
        Ok(())
    }
}

// ── Account ──────────────────────────────────────────────────────────────────

#[account]
pub struct SpendingSessionAccount {
    /// Wallet that created this session
    pub owner: Pubkey,                       // 32
    /// Which agent this session is for
    pub agent_id: [u8; 32],                  // 32
    /// Unique session identifier
    pub session_id: [u8; 16],                // 16
    /// Maximum USDC amount (in micro-units, 6 decimals)
    pub max_amount_usdc: u64,                // 8
    /// Running total of spent amount
    pub spent_so_far: u64,                   // 8
    /// Unix timestamp when session expires
    pub expires_at: i64,                     // 8
    /// Up to 10 allowed merchant identifiers (32 bytes each)
    pub allowed_merchants: [[u8; 32]; 10],   // 320
    /// Number of valid merchants in the array
    pub merchant_count: u8,                  // 1
    /// 0=Active, 1=Exhausted, 2=Expired, 3=Revoked
    pub status: u8,                          // 1
    /// Snapshot of policy hash at session creation
    pub policy_hash: [u8; 32],               // 32
    /// When the session was created
    pub created_at: i64,                     // 8
    /// PDA bump seed
    pub bump: u8,                            // 1
}

// Total: 8 (discriminator) + 32+32+16+8+8+8+320+1+1+32+8+1 = 475

impl SpendingSessionAccount {
    pub const LEN: usize = 8 + 32 + 32 + 16 + 8 + 8 + 8 + 320 + 1 + 1 + 32 + 8 + 1;
}

#[derive(Clone, Copy, PartialEq)]
pub enum SessionStatus {
    Active = 0,
    Exhausted = 1,
    Expired = 2,
    Revoked = 3,
}

// ── Contexts ─────────────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(session_id: [u8; 16])]
pub struct CreateSession<'info> {
    #[account(
        init,
        payer = owner,
        space = SpendingSessionAccount::LEN,
        seeds = [b"session", owner.key().as_ref(), &session_id],
        bump,
    )]
    pub session_account: Account<'info, SpendingSessionAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SpendFromSession<'info> {
    #[account(
        mut,
        seeds = [b"session", owner.key().as_ref(), &session_account.session_id],
        bump = session_account.bump,
        has_one = owner @ SessionError::Unauthorized,
    )]
    pub session_account: Account<'info, SpendingSessionAccount>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct RevokeSession<'info> {
    #[account(
        mut,
        seeds = [b"session", owner.key().as_ref(), &session_account.session_id],
        bump = session_account.bump,
        has_one = owner @ SessionError::Unauthorized,
    )]
    pub session_account: Account<'info, SpendingSessionAccount>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseSession<'info> {
    #[account(
        mut,
        seeds = [b"session", owner.key().as_ref(), &session_account.session_id],
        bump = session_account.bump,
        has_one = owner @ SessionError::Unauthorized,
        constraint = session_account.status != SessionStatus::Active as u8 @ SessionError::CannotCloseActive,
        close = owner,
    )]
    pub session_account: Account<'info, SpendingSessionAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

// ── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct SessionCreated {
    pub owner: Pubkey,
    pub session_id: [u8; 16],
    pub agent_id: [u8; 32],
    pub max_amount_usdc: u64,
    pub expires_at: i64,
    pub timestamp: i64,
}

#[event]
pub struct SessionSpent {
    pub owner: Pubkey,
    pub session_id: [u8; 16],
    pub amount_usdc: u64,
    pub new_total: u64,
    pub remaining: u64,
    pub merchant: [u8; 32],
    pub timestamp: i64,
}

#[event]
pub struct SessionExhausted {
    pub owner: Pubkey,
    pub session_id: [u8; 16],
    pub total_spent: u64,
    pub timestamp: i64,
}

#[event]
pub struct SessionRevoked {
    pub owner: Pubkey,
    pub session_id: [u8; 16],
    pub spent_so_far: u64,
    pub timestamp: i64,
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum SessionError {
    #[msg("Only the session owner can perform this action")]
    Unauthorized,
    #[msg("Session is not active")]
    SessionNotActive,
    #[msg("Session has expired")]
    SessionExpired,
    #[msg("Spending would exceed session budget")]
    BudgetExceeded,
    #[msg("Merchant not in session allowlist")]
    MerchantNotAllowed,
    #[msg("Expiration must be in the future")]
    InvalidExpiration,
    #[msg("Amount must be greater than zero")]
    InvalidAmount,
    #[msg("Maximum 10 merchants per session")]
    TooManyMerchants,
    #[msg("Cannot close an active session — revoke it first")]
    CannotCloseActive,
}
