-- Migration: Add arc-testnet to chain enum
ALTER TYPE chain ADD VALUE IF NOT EXISTS 'arc-testnet';
