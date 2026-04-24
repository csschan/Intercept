/**
 * IDL for the policy_registry Anchor program.
 * Discriminators computed from sha256("global:<snake_case>")[:8] for instructions
 * and sha256("account:<PascalCase>")[:8] for accounts.
 */
export const IDL = {
  address: 'FKvRpAWkPHh6HqQkvSfABAkrMrhaJz195q5Rw2NvznGG',
  metadata: {
    name: 'policy_registry',
    version: '0.1.0',
    spec: '0.1.0',
    description: 'Intercept on-chain policy registry',
  },
  instructions: [
    {
      name: 'initializePolicy',
      discriminator: [9, 186, 86, 225, 129, 162, 231, 56],
      accounts: [
        { name: 'policyAccount', writable: true, pda: { seeds: [{ kind: 'const', value: [112, 111, 108, 105, 99, 121] }, { kind: 'account', path: 'owner' }, { kind: 'arg', path: 'agentId' }] } },
        { name: 'owner', writable: true, signer: true },
        { name: 'systemProgram', address: '11111111111111111111111111111111' },
      ],
      args: [
        { name: 'agentId', type: { array: ['u8', 32] } },
        { name: 'policyHash', type: { array: ['u8', 32] } },
        { name: 'metadataUri', type: 'string' },
      ],
    },
    {
      name: 'updatePolicy',
      discriminator: [212, 245, 246, 7, 163, 151, 18, 57],
      accounts: [
        { name: 'policyAccount', writable: true, pda: { seeds: [{ kind: 'const', value: [112, 111, 108, 105, 99, 121] }, { kind: 'account', path: 'owner' }, { kind: 'account', path: 'policyAccount', fieldPath: 'agentId' }] } },
        { name: 'owner', signer: true },
      ],
      args: [
        { name: 'newHash', type: { array: ['u8', 32] } },
        { name: 'metadataUri', type: 'string' },
      ],
    },
    {
      name: 'verifyPolicy',
      discriminator: [198, 175, 207, 241, 67, 9, 94, 55],
      accounts: [
        { name: 'policyAccount', pda: { seeds: [{ kind: 'const', value: [112, 111, 108, 105, 99, 121] }, { kind: 'account', path: 'policyAccount', fieldPath: 'owner' }, { kind: 'account', path: 'policyAccount', fieldPath: 'agentId' }] } },
      ],
      args: [
        { name: 'claimedHash', type: { array: ['u8', 32] } },
      ],
    },
    {
      name: 'closePolicy',
      discriminator: [55, 42, 248, 229, 222, 138, 26, 252],
      accounts: [
        { name: 'policyAccount', writable: true, pda: { seeds: [{ kind: 'const', value: [112, 111, 108, 105, 99, 121] }, { kind: 'account', path: 'owner' }, { kind: 'account', path: 'policyAccount', fieldPath: 'agentId' }] } },
        { name: 'owner', writable: true, signer: true },
      ],
      args: [],
    },
  ],
  accounts: [
    {
      name: 'PolicyAccount',
      discriminator: [218, 201, 183, 164, 156, 127, 81, 175],
    },
  ],
  events: [],
  errors: [
    { code: 6000, name: 'Unauthorized', msg: 'Only the policy owner can perform this action' },
    { code: 6001, name: 'MetadataUriTooLong', msg: 'Metadata URI must be 128 characters or less' },
  ],
  types: [
    {
      name: 'PolicyAccount',
      type: {
        kind: 'struct',
        fields: [
          { name: 'owner', type: 'pubkey' },
          { name: 'agentId', type: { array: ['u8', 32] } },
          { name: 'policyHash', type: { array: ['u8', 32] } },
          { name: 'metadataUri', type: 'string' },
          { name: 'version', type: 'u32' },
          { name: 'updatedAt', type: 'i64' },
          { name: 'bump', type: 'u8' },
        ],
      },
    },
  ],
} as const
