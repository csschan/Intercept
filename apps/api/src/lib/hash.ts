/**
 * Credential Hashing
 *
 * API keys and session keys are high-entropy random strings,
 * so SHA-256 is sufficient (no need for bcrypt/argon2 which are
 * designed for low-entropy passwords).
 */

import { createHash } from 'crypto'

export function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex')
}

export function hashSessionKey(key: string): string {
  return createHash('sha256').update(key).digest('hex')
}
