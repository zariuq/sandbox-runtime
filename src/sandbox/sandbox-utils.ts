import shellquote from 'shell-quote'
import { homedir } from 'os'
import * as path from 'path'
import * as fs from 'fs'

/**
 * Dangerous files that should be protected from writes.
 * These files can be used for code execution or data exfiltration.
 */
export const DANGEROUS_FILES = [
  '.gitconfig',
  '.gitmodules',
  '.bashrc',
  '.bash_profile',
  '.zshrc',
  '.zprofile',
  '.profile',
  '.ripgreprc',
  '.mcp.json',
] as const

/**
 * Dangerous directories that should be protected from writes.
 * These directories contain sensitive configuration or executable files.
 */
export const DANGEROUS_DIRECTORIES = ['.git', '.vscode', '.idea'] as const

/**
 * Get the list of dangerous directories to deny writes to.
 * Excludes .git since we need it writable for git operations -
 * instead we block specific paths within .git (hooks and config).
 */
export function getDangerousDirectories(): string[] {
  return [
    ...DANGEROUS_DIRECTORIES.filter(d => d !== '.git'),
    '.claude/commands',
    '.claude/agents',
  ]
}

/**
 * Normalizes a path for case-insensitive comparison.
 * This prevents bypassing security checks using mixed-case paths on case-insensitive
 * filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.
 *
 * We always normalize to lowercase regardless of platform for consistent security.
 * @param path The path to normalize
 * @returns The lowercase path for safe comparison
 */
export function normalizeCaseForComparison(pathStr: string): string {
  return pathStr.toLowerCase()
}

/**
 * Check if a path pattern contains glob characters
 */
export function containsGlobChars(pathPattern: string): boolean {
  return (
    pathPattern.includes('*') ||
    pathPattern.includes('?') ||
    pathPattern.includes('[') ||
    pathPattern.includes(']')
  )
}

/**
 * Remove trailing /** glob suffix from a path pattern
 * Used to normalize path patterns since /** just means "directory and everything under it"
 */
export function removeTrailingGlobSuffix(pathPattern: string): string {
  return pathPattern.replace(/\/\*\*$/, '')
}

function normalizePathWithoutResolvingSymlinks(pathPattern: string): string {
  const cwd = process.cwd()

  if (pathPattern === '~') {
    return homedir()
  }

  if (pathPattern.startsWith('~/')) {
    return homedir() + pathPattern.slice(1)
  }

  if (pathPattern.startsWith('./') || pathPattern.startsWith('../')) {
    return path.resolve(cwd, pathPattern)
  }

  if (!path.isAbsolute(pathPattern)) {
    return path.resolve(cwd, pathPattern)
  }

  return pathPattern
}

/**
 * Normalize a path for use in sandbox configurations
 * Handles:
 * - Tilde (~) expansion for home directory
 * - Relative paths (./foo, ../foo, etc.) converted to absolute
 * - Absolute paths remain unchanged
 * - Symlinks are resolved to their real paths for non-glob patterns
 * - Glob patterns preserve wildcards after path normalization
 *
 * Returns the absolute path with symlinks resolved (or normalized glob pattern)
 */
export function normalizePathForSandbox(pathPattern: string): string {
  let normalizedPath = normalizePathWithoutResolvingSymlinks(pathPattern)

  // For glob patterns, resolve symlinks for the directory portion only
  if (containsGlobChars(normalizedPath)) {
    // Extract the static directory prefix before glob characters
    const staticPrefix = normalizedPath.split(/[*?[\]]/)[0]
    if (staticPrefix && staticPrefix !== '/') {
      // Get the directory containing the glob pattern
      // If staticPrefix ends with /, remove it to get the directory
      const baseDir = staticPrefix.endsWith('/')
        ? staticPrefix.slice(0, -1)
        : path.dirname(staticPrefix)

      // Try to resolve symlinks for the base directory
      try {
        const resolvedBaseDir = fs.realpathSync(baseDir)
        // Reconstruct the pattern with the resolved directory
        const patternSuffix = normalizedPath.slice(baseDir.length)
        return resolvedBaseDir + patternSuffix
      } catch {
        // If directory doesn't exist or can't be resolved, keep the original pattern
      }
    }
    return normalizedPath
  }

  // Resolve symlinks to real paths to avoid bwrap issues
  try {
    normalizedPath = fs.realpathSync(normalizedPath)
  } catch {
    // If path doesn't exist or can't be resolved, keep the normalized path
  }

  return normalizedPath
}

function getUserSpaceRuntimeRoot(executablePath: string): string | undefined {
  const binDir = path.dirname(executablePath)
  if (path.basename(binDir) !== 'bin') {
    return undefined
  }

  const runtimeRoot = path.dirname(binDir)
  if (runtimeRoot === path.sep) {
    return undefined
  }

  const homeDir = homedir()
  const allowedPrefixes = [homeDir, '/tmp', '/private/tmp']
  if (
    !allowedPrefixes.some(
      prefix =>
        runtimeRoot === prefix || runtimeRoot.startsWith(prefix + path.sep),
    )
  ) {
    return undefined
  }

  const markerPaths = [
    path.join(runtimeRoot, 'pyvenv.cfg'),
    path.join(runtimeRoot, 'conda-meta'),
    path.join(runtimeRoot, 'lib'),
  ]

  return markerPaths.some(marker => fs.existsSync(marker))
    ? runtimeRoot
    : undefined
}

function parseAbsoluteShebangInterpreter(filePath: string): string | undefined {
  try {
    const fd = fs.openSync(filePath, 'r')
    try {
      const buf = Buffer.alloc(256)
      const bytesRead = fs.readSync(fd, buf, 0, buf.length, 0)
      if (bytesRead < 2 || buf[0] !== 0x23 || buf[1] !== 0x21) {
        return undefined
      }

      const firstLine = buf
        .subarray(0, bytesRead)
        .toString('utf8')
        .split('\n', 1)[0]
      const shebang = firstLine.slice(2).trim()
      if (shebang.length === 0) {
        return undefined
      }

      const [interpreterPath] = shebang.split(/\s+/, 1)
      return interpreterPath.startsWith('/') ? interpreterPath : undefined
    } finally {
      fs.closeSync(fd)
    }
  } catch {
    return undefined
  }
}

/**
 * Expand executable entrypoints into the narrow read carve-outs needed to run them
 * inside a read-restricted sandbox:
 * - the lexical path the caller configured
 * - the resolved executable target
 * - common user-space runtime roots for virtualenv/conda-style layouts
 * - absolute shebang interpreters plus their runtime roots
 */
export function getExecutableReadPathsForSandbox(
  executablePathPatterns: string[],
): string[] {
  const expandedPaths = new Set<string>()
  const queue: string[] = []
  const inspectedFiles = new Set<string>()

  const enqueuePath = (pathPattern: string): void => {
    if (!pathPattern) {
      return
    }

    if (!expandedPaths.has(pathPattern)) {
      expandedPaths.add(pathPattern)
    }

    if (!queue.includes(pathPattern)) {
      queue.push(pathPattern)
    }
  }

  const addRuntimeRoot = (filePath: string): void => {
    const runtimeRoot = getUserSpaceRuntimeRoot(filePath)
    if (runtimeRoot) {
      expandedPaths.add(runtimeRoot)
    }
  }

  for (const pathPattern of executablePathPatterns) {
    const lexicalPath = normalizePathWithoutResolvingSymlinks(pathPattern)
    enqueuePath(lexicalPath)

    try {
      enqueuePath(fs.realpathSync(lexicalPath))
    } catch {
      // Keep the lexical path even if the target is absent.
    }
  }

  while (queue.length > 0) {
    const filePath = queue.shift()
    if (!filePath || inspectedFiles.has(filePath)) {
      continue
    }
    inspectedFiles.add(filePath)

    if (!fs.existsSync(filePath)) {
      continue
    }

    let stat: fs.Stats
    try {
      stat = fs.statSync(filePath)
    } catch {
      continue
    }

    if (!stat.isFile()) {
      continue
    }

    addRuntimeRoot(filePath)

    const interpreterPath = parseAbsoluteShebangInterpreter(filePath)
    if (!interpreterPath) {
      continue
    }

    enqueuePath(interpreterPath)

    try {
      enqueuePath(fs.realpathSync(interpreterPath))
    } catch {
      // Keep the lexical interpreter path if the target is absent.
    }
  }

  return [...expandedPaths]
}

/**
 * Get recommended system paths that should be writable for commands to work properly
 *
 * WARNING: These default paths are intentionally broad for compatibility but may
 * allow access to files from other processes. In highly security-sensitive
 * environments, you should configure more restrictive write paths.
 */
export function getDefaultWritePaths(): string[] {
  const homeDir = homedir()
  const recommendedPaths = [
    '/dev/stdout',
    '/dev/stderr',
    '/dev/null',
    '/dev/tty',
    '/dev/dtracehelper',
    '/dev/autofs_nowait',
    '/tmp/claude',
    '/private/tmp/claude',
    path.join(homeDir, '.npm/_logs'),
    path.join(homeDir, '.claude/debug'),
  ]

  return recommendedPaths
}

/**
 * Generate proxy environment variables for sandboxed processes
 */
export function generateProxyEnvVars(
  httpProxyPort?: number,
  socksProxyPort?: number,
): string[] {
  const envVars: string[] = [`SANDBOX_RUNTIME=1`, `TMPDIR=/tmp/claude`]
  const loopbackHost = '127.0.0.1'

  // If no proxy ports provided, return minimal env vars
  if (!httpProxyPort && !socksProxyPort) {
    return envVars
  }

  // Always set NO_PROXY to exclude localhost and private networks from proxying
  const noProxyAddresses = [
    'localhost',
    '127.0.0.1',
    '::1',
    '*.local',
    '.local',
    '169.254.0.0/16', // Link-local
    '10.0.0.0/8', // Private network
    '172.16.0.0/12', // Private network
    '192.168.0.0/16', // Private network
  ].join(',')
  envVars.push(`NO_PROXY=${noProxyAddresses}`)
  envVars.push(`no_proxy=${noProxyAddresses}`)

  if (httpProxyPort) {
    envVars.push(`HTTP_PROXY=http://${loopbackHost}:${httpProxyPort}`)
    envVars.push(`HTTPS_PROXY=http://${loopbackHost}:${httpProxyPort}`)
    // Lowercase versions for compatibility with some tools
    envVars.push(`http_proxy=http://${loopbackHost}:${httpProxyPort}`)
    envVars.push(`https_proxy=http://${loopbackHost}:${httpProxyPort}`)
  }

  if (socksProxyPort) {
    // Use socks5h:// for proper DNS resolution through proxy
    envVars.push(`ALL_PROXY=socks5h://${loopbackHost}:${socksProxyPort}`)
    envVars.push(`all_proxy=socks5h://${loopbackHost}:${socksProxyPort}`)

    envVars.push(
      `GIT_SSH_COMMAND=ssh -o ProxyCommand='nc -X 5 -x ${loopbackHost}:${socksProxyPort} %h %p' -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/srt-ssh-known-hosts`,
    )
    envVars.push('SSH_ASKPASS_REQUIRE=never')

    // FTP proxy support (use socks5h for DNS resolution through proxy)
    envVars.push(`FTP_PROXY=socks5h://${loopbackHost}:${socksProxyPort}`)
    envVars.push(`ftp_proxy=socks5h://${loopbackHost}:${socksProxyPort}`)

    // rsync proxy support
    envVars.push(`RSYNC_PROXY=${loopbackHost}:${socksProxyPort}`)

    // Database tools NOTE: Most database clients don't have built-in proxy support
    // You typically need to use SSH tunneling or a SOCKS wrapper like tsocks/proxychains

    // Docker CLI uses HTTP for the API
    // This makes Docker use the HTTP proxy for registry operations
    envVars.push(
      `DOCKER_HTTP_PROXY=http://${loopbackHost}:${httpProxyPort || socksProxyPort}`,
    )
    envVars.push(
      `DOCKER_HTTPS_PROXY=http://${loopbackHost}:${httpProxyPort || socksProxyPort}`,
    )

    // Kubernetes kubectl - uses standard HTTPS_PROXY
    // kubectl respects HTTPS_PROXY which we already set above

    // AWS CLI - uses standard HTTPS_PROXY (v2 supports it well)
    // AWS CLI v2 respects HTTPS_PROXY which we already set above

    // Google Cloud SDK - has specific proxy settings
    // Use HTTPS proxy to match other HTTP-based tools
    if (httpProxyPort) {
      envVars.push(`CLOUDSDK_PROXY_TYPE=https`)
      envVars.push(`CLOUDSDK_PROXY_ADDRESS=${loopbackHost}`)
      envVars.push(`CLOUDSDK_PROXY_PORT=${httpProxyPort}`)
    }

    // Azure CLI - uses HTTPS_PROXY
    // Azure CLI respects HTTPS_PROXY which we already set above

    // Terraform - uses standard HTTP/HTTPS proxy vars
    // Terraform respects HTTP_PROXY/HTTPS_PROXY which we already set above

    // gRPC-based tools - use standard proxy vars
    envVars.push(`GRPC_PROXY=socks5h://${loopbackHost}:${socksProxyPort}`)
    envVars.push(`grpc_proxy=socks5h://${loopbackHost}:${socksProxyPort}`)
  }

  // WARNING: Do not set HTTP_PROXY/HTTPS_PROXY to SOCKS URLs when only SOCKS proxy is available
  // Most HTTP clients do not support SOCKS URLs in these variables and will fail, and we want
  // to avoid overriding the client otherwise respecting the ALL_PROXY env var which points to SOCKS.

  return envVars
}

/**
 * Format KEY=value environment assignments for use in a shell `export` command.
 * Values are shell-quoted so variables like GIT_SSH_COMMAND survive round-trips
 * through `/bin/sh -c` while Linux can still consume the raw values via `--setenv`.
 */
export function formatEnvVarsForShellExport(envVars: string[]): string {
  const assignments = envVars.map(env => {
    const firstEq = env.indexOf('=')
    const key = env.slice(0, firstEq)
    const value = env.slice(firstEq + 1)
    return `${key}=${shellquote.quote([value])}`
  })

  return `export ${assignments.join(' ')}`
}

/**
 * Encode a command for sandbox monitoring
 * Truncates to 100 chars and base64 encodes to avoid parsing issues
 */
export function encodeSandboxedCommand(command: string): string {
  const truncatedCommand = command.slice(0, 100)
  return Buffer.from(truncatedCommand).toString('base64')
}

/**
 * Decode a base64-encoded command from sandbox monitoring
 */
export function decodeSandboxedCommand(encodedCommand: string): string {
  return Buffer.from(encodedCommand, 'base64').toString('utf8')
}
