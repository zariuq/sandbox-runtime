/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */

import { z } from 'zod'

/**
 * Schema for domain patterns (e.g., "example.com", "*.npmjs.org")
 * Validates that domain patterns are safe and don't include overly broad wildcards
 */
const domainPatternSchema = z.string().refine(
  val => {
    // Reject protocols, paths, ports, etc.
    if (val.includes('://') || val.includes('/') || val.includes(':')) {
      return false
    }

    // Allow localhost
    if (val === 'localhost') return true

    // Allow wildcard domains like *.example.com
    if (val.startsWith('*.')) {
      const domain = val.slice(2)
      // After the *. there must be a valid domain with at least one more dot
      // e.g., *.example.com is valid, *.com is not (too broad)
      if (
        !domain.includes('.') ||
        domain.startsWith('.') ||
        domain.endsWith('.')
      ) {
        return false
      }
      // Count dots - must have at least 2 parts after the wildcard (e.g., example.com)
      const parts = domain.split('.')
      return parts.length >= 2 && parts.every(p => p.length > 0)
    }

    // Reject any other use of wildcards (e.g., *, *., etc.)
    if (val.includes('*')) {
      return false
    }

    // Regular domains must have at least one dot and only valid characters
    return val.includes('.') && !val.startsWith('.') && !val.endsWith('.')
  },
  {
    message:
      'Invalid domain pattern. Must be a valid domain (e.g., "example.com") or wildcard (e.g., "*.example.com"). Overly broad patterns like "*.com" or "*" are not allowed for security reasons.',
  },
)

/**
 * Schema for filesystem paths
 */
const filesystemPathSchema = z.string().min(1, 'Path cannot be empty')

export const DeviceAccessClassSchema = z.enum([
  'gpu',
  'kvm',
  'fuse',
  'tun',
  'serial',
  'video',
  'usb',
  'input',
  'tpm',
  'vfio',
  'rawBlock',
])

export const DeviceAccessConfigSchema = z.object({
  allowAll: z
    .boolean()
    .optional()
    .describe(
      'Allow all known host device classes except those explicitly denied (default: true).',
    ),
  allow: z
    .array(DeviceAccessClassSchema)
    .optional()
    .describe(
      'Device classes to expose when allowAll is false. Ignored when allowAll is true.',
    ),
  deny: z
    .array(DeviceAccessClassSchema)
    .optional()
    .describe(
      'Device classes to hide when allowAll is true, or to subtract from allow when allowAll is false.',
    ),
})

/**
 * Network configuration schema for validation
 */
export const NetworkConfigSchema = z.object({
  allowAll: z
    .boolean()
    .optional()
    .describe(
      'Allow ALL network connections except those explicitly denied. ' +
        'When true, allowedDomains is ignored and all connections are permitted unless in deniedDomains. ' +
        'WARNING: This significantly reduces security - use with caution and maintain a deny list.',
    ),
  allowedDomains: z
    .array(domainPatternSchema)
    .describe('List of allowed domains (e.g., ["github.com", "*.npmjs.org"])'),
  deniedDomains: z
    .array(domainPatternSchema)
    .describe('List of denied domains'),
  blockPrivateIPs: z
    .boolean()
    .optional()
    .describe(
      'Block connections to private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). ' +
        'Recommended when using allowAll to prevent access to localhost services, internal networks, and cloud metadata endpoints (default: false).',
    ),
  allowUnixSockets: z
    .array(z.string())
    .optional()
    .describe(
      'Unix socket paths that are allowed on macOS. Linux currently allows Unix sockets unconditionally.',
    ),
  allowAllUnixSockets: z
    .boolean()
    .optional()
    .describe(
      'Allow all Unix sockets. On macOS this disables Unix socket restrictions; on Linux it is accepted for backward compatibility and is currently a no-op.',
    ),
  allowLocalBinding: z
    .boolean()
    .optional()
    .describe('Whether to allow binding to local ports (default: false)'),
  httpProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external HTTP proxy to use instead of starting a local one. When provided, the library will skip starting its own HTTP proxy and use this port. The external proxy must handle domain filtering.',
    ),
  socksProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external SOCKS proxy to use instead of starting a local one. When provided, the library will skip starting its own SOCKS proxy and use this port. The external proxy must handle domain filtering.',
    ),
})

/**
 * Filesystem configuration schema for validation
 */
export const FilesystemConfigSchema = z.object({
  denyRead: z.array(filesystemPathSchema).describe('Paths denied for reading'),
  allowRead: z
    .array(filesystemPathSchema)
    .optional()
    .describe(
      'Paths allowed for reading even if a parent path is denied for reading',
    ),
  allowExec: z
    .array(filesystemPathSchema)
    .optional()
    .describe(
      'Executable entrypoints that should remain runnable even if their symlink targets or runtime prefixes live under denied read paths. ' +
        'SRT expands each entry into narrow read carve-outs for the resolved executable, common user-space runtime roots, and absolute shebang interpreters.',
    ),
  denyReadWithinAllow: z
    .array(filesystemPathSchema)
    .optional()
    .describe('Paths denied for reading again within an allowRead re-exposure'),
  allowWrite: z
    .array(filesystemPathSchema)
    .describe('Paths allowed for writing'),
  denyWrite: z
    .array(filesystemPathSchema)
    .describe('Paths denied for writing (takes precedence over allowWrite)'),
  allowWriteWithinDeny: z
    .array(filesystemPathSchema)
    .optional()
    .describe(
      'Paths allowed for writing again within a denyWrite re-mask. ' +
        'Useful for broad write denies with narrow writable carve-outs (Linux only).',
    ),
  allowGitConfig: z
    .boolean()
    .optional()
    .describe(
      'Allow writes to .git/config files (default: false). Enables git remote URL updates while keeping .git/hooks protected.',
    ),
})

/**
 * Configuration schema for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 */
export const IgnoreViolationsConfigSchema = z
  .record(z.string(), z.array(z.string()))
  .describe(
    'Map of command patterns to filesystem paths to ignore violations for. Use "*" to match all commands',
  )

/**
 * Ripgrep configuration schema
 */
export const RipgrepConfigSchema = z.object({
  command: z
    .string()
    .describe('The ripgrep command to execute (e.g., "rg", "claude")'),
  args: z
    .array(z.string())
    .optional()
    .describe(
      'Additional arguments to pass before ripgrep args (e.g., ["--ripgrep"])',
    ),
})

/**
 * Main configuration schema for Sandbox Runtime validation
 */
export const SandboxRuntimeConfigSchema = z.object({
  network: NetworkConfigSchema.describe('Network restrictions configuration'),
  filesystem: FilesystemConfigSchema.describe(
    'Filesystem restrictions configuration',
  ),
  devices: DeviceAccessConfigSchema.optional().describe(
    'Host device passthrough policy for Linux sandboxes',
  ),
  ignoreViolations: IgnoreViolationsConfigSchema.optional().describe(
    'Optional configuration for ignoring specific violations',
  ),
  enableWeakerNestedSandbox: z
    .boolean()
    .optional()
    .describe('Enable weaker nested sandbox mode (for Docker environments)'),
  ripgrep: RipgrepConfigSchema.optional().describe(
    'Custom ripgrep configuration (default: { command: "rg" })',
  ),
  mandatoryDenySearchDepth: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe(
      'Maximum directory depth to search for dangerous files on Linux (default: 3). ' +
        'Higher values provide more protection but slower performance.',
    ),
  allowPty: z
    .boolean()
    .optional()
    .describe('Allow pseudo-terminal (pty) operations (macOS only)'),
})

// Export inferred types
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>
export type FilesystemConfig = z.infer<typeof FilesystemConfigSchema>
export type DeviceAccessClass = z.infer<typeof DeviceAccessClassSchema>
export type DeviceAccessConfig = z.infer<typeof DeviceAccessConfigSchema>
export type IgnoreViolationsConfig = z.infer<
  typeof IgnoreViolationsConfigSchema
>
export type RipgrepConfig = z.infer<typeof RipgrepConfigSchema>
export type SandboxRuntimeConfig = z.infer<typeof SandboxRuntimeConfigSchema>
