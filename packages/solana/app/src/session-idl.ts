/**
 * IDL for the spending_session Anchor program.
 */
export const SESSION_IDL = {
  address: 'DmBoKbEr7rcdcdCEFq94w2rfF6EtSthxqhSM25uCnFDG',
  metadata: {
    name: 'spending_session',
    version: '0.1.0',
    spec: '0.1.0',
    description: 'Intercept on-chain spending session authority',
  },
  instructions: [
    {
      name: 'createSession',
      discriminator: [242, 193, 143, 179, 150, 25, 122, 227],
      accounts: [
        { name: 'sessionAccount', writable: true, pda: { seeds: [{ kind: 'const', value: [115, 101, 115, 115, 105, 111, 110] }, { kind: 'account', path: 'owner' }, { kind: 'arg', path: 'sessionId' }] } },
        { name: 'owner', writable: true, signer: true },
        { name: 'systemProgram', address: '11111111111111111111111111111111' },
      ],
      args: [
        { name: 'sessionId', type: { array: ['u8', 16] } },
        { name: 'agentId', type: { array: ['u8', 32] } },
        { name: 'maxAmountUsdc', type: 'u64' },
        { name: 'expiresAt', type: 'i64' },
        { name: 'allowedMerchants', type: { vec: { array: ['u8', 32] } } },
        { name: 'policyHash', type: { array: ['u8', 32] } },
      ],
    },
    {
      name: 'spendFromSession',
      discriminator: [33, 10, 24, 183, 244, 176, 89, 8],
      accounts: [
        { name: 'sessionAccount', writable: true, pda: { seeds: [{ kind: 'const', value: [115, 101, 115, 115, 105, 111, 110] }, { kind: 'account', path: 'owner' }, { kind: 'account', path: 'sessionAccount', fieldPath: 'sessionId' }] } },
        { name: 'owner', signer: true },
      ],
      args: [
        { name: 'amountUsdc', type: 'u64' },
        { name: 'merchant', type: { array: ['u8', 32] } },
      ],
    },
    {
      name: 'revokeSession',
      discriminator: [86, 92, 198, 120, 144, 2, 7, 194],
      accounts: [
        { name: 'sessionAccount', writable: true, pda: { seeds: [{ kind: 'const', value: [115, 101, 115, 115, 105, 111, 110] }, { kind: 'account', path: 'owner' }, { kind: 'account', path: 'sessionAccount', fieldPath: 'sessionId' }] } },
        { name: 'owner', signer: true },
      ],
      args: [],
    },
    {
      name: 'closeSession',
      discriminator: [68, 114, 178, 140, 222, 38, 248, 211],
      accounts: [
        { name: 'sessionAccount', writable: true, pda: { seeds: [{ kind: 'const', value: [115, 101, 115, 115, 105, 111, 110] }, { kind: 'account', path: 'owner' }, { kind: 'account', path: 'sessionAccount', fieldPath: 'sessionId' }] } },
        { name: 'owner', writable: true, signer: true },
      ],
      args: [],
    },
  ],
  accounts: [
    {
      name: 'SpendingSessionAccount',
      discriminator: [47, 223, 130, 25, 104, 103, 70, 15],
    },
  ],
  events: [],
  errors: [
    { code: 6000, name: 'Unauthorized', msg: 'Only the session owner can perform this action' },
    { code: 6001, name: 'SessionNotActive', msg: 'Session is not active' },
    { code: 6002, name: 'SessionExpired', msg: 'Session has expired' },
    { code: 6003, name: 'BudgetExceeded', msg: 'Spending would exceed session budget' },
    { code: 6004, name: 'MerchantNotAllowed', msg: 'Merchant not in session allowlist' },
    { code: 6005, name: 'InvalidExpiration', msg: 'Expiration must be in the future' },
    { code: 6006, name: 'InvalidAmount', msg: 'Amount must be greater than zero' },
    { code: 6007, name: 'TooManyMerchants', msg: 'Maximum 10 merchants per session' },
    { code: 6008, name: 'CannotCloseActive', msg: 'Cannot close an active session — revoke it first' },
  ],
  types: [
    {
      name: 'SpendingSessionAccount',
      type: {
        kind: 'struct',
        fields: [
          { name: 'owner', type: 'pubkey' },
          { name: 'agentId', type: { array: ['u8', 32] } },
          { name: 'sessionId', type: { array: ['u8', 16] } },
          { name: 'maxAmountUsdc', type: 'u64' },
          { name: 'spentSoFar', type: 'u64' },
          { name: 'expiresAt', type: 'i64' },
          { name: 'allowedMerchants', type: { array: [{ array: ['u8', 32] }, 10] } },
          { name: 'merchantCount', type: 'u8' },
          { name: 'status', type: 'u8' },
          { name: 'policyHash', type: { array: ['u8', 32] } },
          { name: 'createdAt', type: 'i64' },
          { name: 'bump', type: 'u8' },
        ],
      },
    },
  ],
} as const
