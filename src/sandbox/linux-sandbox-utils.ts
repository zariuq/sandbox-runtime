import shellquote from 'shell-quote'
import { logForDebugging } from '../utils/debug.js'
import { createHash, randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { tmpdir } from 'node:os'
import path, { join } from 'node:path'
import { ripGrep } from '../utils/ripgrep.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  normalizeCaseForComparison,
  DANGEROUS_FILES,
  getDangerousDirectories,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import type { DeviceAccessClass, DeviceAccessConfig } from './sandbox-config.js'

export interface LinuxNetworkBridgeContext {
  httpSocketPath: string
  socksSocketPath: string
  httpBridgeProcess: ChildProcess
  socksBridgeProcess: ChildProcess
  httpProxyPort: number
  socksProxyPort: number
}

export interface LinuxSandboxParams {
  command: string
  needsNetworkRestriction: boolean
  httpSocketPath?: string
  socksSocketPath?: string
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  enableWeakerNestedSandbox?: boolean
  binShell?: string
  ripgrepConfig?: { command: string; args?: string[] }
  /** Maximum directory depth to search for dangerous files (default: 3) */
  mandatoryDenySearchDepth?: number
  /** Allow writes to .git/config files (default: false) */
  allowGitConfig?: boolean
  /** Host device passthrough policy (default: allow all discovered classes) */
  deviceConfig?: DeviceAccessConfig
  /** Abort signal to cancel the ripgrep scan */
  abortSignal?: AbortSignal
}

/** Default max depth for searching dangerous files */
const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3

const LINUX_DEVICE_EXACT_PATHS: Array<{
  deviceClass: DeviceAccessClass
  path: string
}> = [
  { deviceClass: 'gpu', path: '/dev/dri' },
  { deviceClass: 'gpu', path: '/dev/kfd' },
  { deviceClass: 'gpu', path: '/dev/dxg' },
  { deviceClass: 'gpu', path: '/dev/nvidia-caps' },
  { deviceClass: 'kvm', path: '/dev/kvm' },
  { deviceClass: 'fuse', path: '/dev/fuse' },
  { deviceClass: 'tun', path: '/dev/net/tun' },
  { deviceClass: 'usb', path: '/dev/bus/usb' },
  { deviceClass: 'input', path: '/dev/input' },
  { deviceClass: 'vfio', path: '/dev/vfio' },
]

const LINUX_DEVICE_PREFIX_MAPPINGS: Array<{
  deviceClass: DeviceAccessClass
  prefix: string
}> = [
  { deviceClass: 'gpu', prefix: 'nvidia' },
  { deviceClass: 'serial', prefix: 'ttyUSB' },
  { deviceClass: 'serial', prefix: 'ttyACM' },
  { deviceClass: 'video', prefix: 'video' },
  { deviceClass: 'video', prefix: 'media' },
  { deviceClass: 'tpm', prefix: 'tpm' },
  { deviceClass: 'tpm', prefix: 'tpmrm' },
  { deviceClass: 'rawBlock', prefix: 'sd' },
  { deviceClass: 'rawBlock', prefix: 'nvme' },
  { deviceClass: 'rawBlock', prefix: 'dm-' },
  { deviceClass: 'rawBlock', prefix: 'loop' },
]

function isLinuxDeviceClassAllowed(
  deviceClass: DeviceAccessClass,
  deviceConfig: DeviceAccessConfig | undefined,
): boolean {
  const allowAll = deviceConfig?.allowAll ?? true
  const allowedSet = new Set(deviceConfig?.allow ?? [])
  const deniedSet = new Set(deviceConfig?.deny ?? [])

  if (allowAll) {
    return !deniedSet.has(deviceClass)
  }

  return allowedSet.has(deviceClass) && !deniedSet.has(deviceClass)
}

function getLinuxHostDevicePassthroughEntries(
  deviceConfig: DeviceAccessConfig | undefined,
): Array<{ deviceClass: DeviceAccessClass; path: string }> {
  const passthroughEntries = new Map<string, DeviceAccessClass>()

  for (const { deviceClass, path: devicePath } of LINUX_DEVICE_EXACT_PATHS) {
    if (
      fs.existsSync(devicePath) &&
      isLinuxDeviceClassAllowed(deviceClass, deviceConfig)
    ) {
      passthroughEntries.set(devicePath, deviceClass)
    }
  }

  try {
    for (const entry of fs.readdirSync('/dev')) {
      for (const { deviceClass, prefix } of LINUX_DEVICE_PREFIX_MAPPINGS) {
        if (
          entry.startsWith(prefix) &&
          isLinuxDeviceClassAllowed(deviceClass, deviceConfig)
        ) {
          const devicePath = path.join('/dev', entry)
          if (fs.existsSync(devicePath)) {
            passthroughEntries.set(devicePath, deviceClass)
          }
        }
      }
    }
  } catch (error) {
    logForDebugging(
      `[Sandbox Linux] Failed to enumerate host /dev entries for passthrough: ${error}`,
    )
  }

  return [...passthroughEntries.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([devicePath, deviceClass]) => ({ deviceClass, path: devicePath }))
}

function appendLinuxHostDevicePassthroughArgs(
  bwrapArgs: string[],
  deviceConfig: DeviceAccessConfig | undefined,
): void {
  const passthroughEntries = getLinuxHostDevicePassthroughEntries(deviceConfig)

  for (const { path: devicePath } of passthroughEntries) {
    // Ordering matters: these binds must come AFTER `--dev /dev`, otherwise the
    // synthetic devtmpfs mount shadows them and host device nodes vanish.
    bwrapArgs.push('--dev-bind-try', devicePath, devicePath)
  }

  if (passthroughEntries.length > 0) {
    const summary = passthroughEntries
      .map(
        ({ deviceClass, path: devicePath }) => `${deviceClass}:${devicePath}`,
      )
      .join(', ')
    logForDebugging(`[Sandbox Linux] Re-exposed host device paths: ${summary}`)
  }
}

/**
 * Check if any existing component in the path is a file (not a directory).
 * If so, the target path can never be created because you can't mkdir under a file.
 */
function hasFileAncestor(targetPath: string): boolean {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue
    const nextPath = currentPath + path.sep + part
    try {
      const stat = fs.statSync(nextPath)
      if (stat.isFile() || stat.isSymbolicLink()) {
        return true
      }
    } catch {
      break
    }
    currentPath = nextPath
  }

  return false
}

/**
 * Find the first non-existent path component.
 */
function findFirstNonExistentComponent(targetPath: string): string {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue
    const nextPath = currentPath + path.sep + part
    if (!fs.existsSync(nextPath)) {
      return nextPath
    }
    currentPath = nextPath
  }

  return targetPath
}

/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 * With --max-depth limiting, this is fast enough to run on each command without memoization.
 */
async function linuxGetMandatoryDenyPaths(
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  maxDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const cwd = process.cwd()
  // Use provided signal or create a fallback controller
  const fallbackController = new AbortController()
  const signal = abortSignal ?? fallbackController.signal
  const dangerousDirectories = getDangerousDirectories()

  // Note: Settings files are added at the callsite in sandbox-manager.ts
  const denyPaths = [
    // Dangerous files in CWD
    ...DANGEROUS_FILES.map(f => path.resolve(cwd, f)),
    // Dangerous directories in CWD
    ...dangerousDirectories.map(d => path.resolve(cwd, d)),
    // Git hooks always blocked for security
    path.resolve(cwd, '.git/hooks'),
  ]

  // Git config conditionally blocked based on allowGitConfig setting
  if (!allowGitConfig) {
    denyPaths.push(path.resolve(cwd, '.git/config'))
  }

  // Build iglob args for all patterns in one ripgrep call
  const iglobArgs: string[] = []
  for (const fileName of DANGEROUS_FILES) {
    iglobArgs.push('--iglob', fileName)
  }
  for (const dirName of dangerousDirectories) {
    iglobArgs.push('--iglob', `**/${dirName}/**`)
  }
  // Git hooks always blocked in nested repos
  iglobArgs.push('--iglob', '**/.git/hooks/**')

  // Git config conditionally blocked in nested repos
  if (!allowGitConfig) {
    iglobArgs.push('--iglob', '**/.git/config')
  }

  // Single ripgrep call to find all dangerous paths in subdirectories
  // Limit depth for performance - deeply nested dangerous files are rare
  // and the security benefit doesn't justify the traversal cost
  let matches: string[] = []
  try {
    matches = await ripGrep(
      [
        '--files',
        '--hidden',
        '--max-depth',
        String(maxDepth),
        ...iglobArgs,
        '-g',
        '!**/node_modules/**',
      ],
      cwd,
      signal,
      ripgrepConfig,
    )
  } catch (error) {
    logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`)
  }

  // Process matches
  for (const match of matches) {
    const absolutePath = path.resolve(cwd, match)

    // File inside a dangerous directory -> add the directory path
    let foundDir = false
    for (const dirName of [...dangerousDirectories, '.git']) {
      const normalizedDirName = normalizeCaseForComparison(dirName)
      const segments = absolutePath.split(path.sep)
      const dirIndex = segments.findIndex(
        s => normalizeCaseForComparison(s) === normalizedDirName,
      )
      if (dirIndex !== -1) {
        // For .git, we want hooks/ or config, not the whole .git dir
        if (dirName === '.git') {
          const gitDir = segments.slice(0, dirIndex + 1).join(path.sep)
          if (match.includes('.git/hooks')) {
            denyPaths.push(path.join(gitDir, 'hooks'))
          } else if (match.includes('.git/config')) {
            denyPaths.push(path.join(gitDir, 'config'))
          }
        } else {
          denyPaths.push(segments.slice(0, dirIndex + 1).join(path.sep))
        }
        foundDir = true
        break
      }
    }

    // Dangerous file match
    if (!foundDir) {
      denyPaths.push(absolutePath)
    }
  }

  return [...new Set(denyPaths)]
}

// Track synthetic mount points created to deny non-existent paths. Bubblewrap
// leaves these host-side mount points behind, so we need explicit cleanup.
const bwrapMountPoints: Set<string> = new Set()

// Cross-process reference tracking prevents one sandbox launch from cleaning up
// a synthetic mount point while another concurrent launch is still using it.
const mountPointStateDir = path.join(tmpdir(), 'claude-bwrap-mountpoint-state')
const MOUNTPOINT_LOCK_RETRY_MS = 10
const MOUNTPOINT_LOCK_TIMEOUT_MS = 5000
const MOUNTPOINT_STALE_LOCK_MS = 10000

type MountPointRefState = {
  path: string
  holders: Record<string, number>
}

const tempEmptyFiles: Set<string> = new Set()
let exitHandlerRegistered = false

/**
 * Small busy wait for tiny cross-process lock windows.
 */
function spinWait(ms: number): void {
  const end = Date.now() + ms
  while (Date.now() < end) {
    // Intentional busy wait.
  }
}

function getMountPointStatePaths(mountPoint: string): {
  statePath: string
  lockPath: string
} {
  const key = createHash('sha256').update(mountPoint).digest('hex')
  return {
    statePath: path.join(mountPointStateDir, `${key}.json`),
    lockPath: path.join(mountPointStateDir, `${key}.lock`),
  }
}

function withMountPointStateLock<T>(
  mountPoint: string,
  fn: (statePath: string) => T,
): T | null {
  fs.mkdirSync(mountPointStateDir, { recursive: true })
  const { statePath, lockPath } = getMountPointStatePaths(mountPoint)
  const deadline = Date.now() + MOUNTPOINT_LOCK_TIMEOUT_MS
  let lockFd: number | null = null

  while (lockFd === null) {
    try {
      lockFd = fs.openSync(lockPath, 'wx')
      break
    } catch (error) {
      const err = error as NodeJS.ErrnoException
      if (err.code !== 'EEXIST') {
        throw error
      }

      try {
        const lockStat = fs.statSync(lockPath)
        if (Date.now() - lockStat.mtimeMs > MOUNTPOINT_STALE_LOCK_MS) {
          fs.unlinkSync(lockPath)
          continue
        }
      } catch {
        // Lock vanished; retry.
      }

      if (Date.now() >= deadline) {
        logForDebugging(
          `[Sandbox Linux] Timed out waiting for mount point lock: ${mountPoint}`,
          { level: 'error' },
        )
        return null
      }
      spinWait(MOUNTPOINT_LOCK_RETRY_MS)
    }
  }

  try {
    return fn(statePath)
  } finally {
    try {
      fs.closeSync(lockFd)
    } catch {
      // Ignore close errors.
    }
    try {
      fs.unlinkSync(lockPath)
    } catch {
      // Ignore unlock errors.
    }
  }
}

function readMountPointRefState(statePath: string): MountPointRefState | null {
  try {
    const raw = fs.readFileSync(statePath, 'utf8')
    const parsed = JSON.parse(raw) as Partial<MountPointRefState>
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof parsed.path !== 'string' ||
      typeof parsed.holders !== 'object' ||
      parsed.holders === null
    ) {
      return null
    }

    const holders: Record<string, number> = {}
    for (const [pidKey, count] of Object.entries(parsed.holders)) {
      if (typeof count === 'number' && Number.isInteger(count) && count > 0) {
        holders[pidKey] = count
      }
    }

    return { path: parsed.path, holders }
  } catch {
    return null
  }
}

function writeMountPointRefState(
  statePath: string,
  state: MountPointRefState,
): void {
  const tmpStatePath = `${statePath}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`
  fs.writeFileSync(tmpStatePath, JSON.stringify(state), 'utf8')
  fs.renameSync(tmpStatePath, statePath)
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false
  }
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    const err = error as NodeJS.ErrnoException
    return err.code === 'EPERM'
  }
}

function pruneDeadHolders(state: MountPointRefState): void {
  for (const pidKey of Object.keys(state.holders)) {
    const pid = Number(pidKey)
    if (!isProcessAlive(pid)) {
      delete state.holders[pidKey]
    }
  }
}

function getTotalHolderCount(state: MountPointRefState): number {
  return Object.values(state.holders).reduce((sum, count) => sum + count, 0)
}

function removeMountPointIfPristine(mountPoint: string): void {
  try {
    const stat = fs.statSync(mountPoint)
    if (stat.isFile() && stat.size === 0) {
      fs.unlinkSync(mountPoint)
      logForDebugging(
        `[Sandbox Linux] Cleaned up bwrap mount point (file): ${mountPoint}`,
      )
    } else if (stat.isDirectory()) {
      const entries = fs.readdirSync(mountPoint)
      if (entries.length === 0) {
        fs.rmdirSync(mountPoint)
        logForDebugging(
          `[Sandbox Linux] Cleaned up bwrap mount point (dir): ${mountPoint}`,
        )
      }
    }
  } catch {
    // Ignore cleanup errors.
  }
}

function acquireMountPointReference(mountPoint: string): void {
  if (bwrapMountPoints.has(mountPoint)) {
    return
  }

  const updated = withMountPointStateLock(mountPoint, statePath => {
    const existingState = readMountPointRefState(statePath)
    const state: MountPointRefState =
      existingState && existingState.path === mountPoint
        ? existingState
        : { path: mountPoint, holders: {} }

    pruneDeadHolders(state)

    const pidKey = String(process.pid)
    state.holders[pidKey] = (state.holders[pidKey] ?? 0) + 1
    writeMountPointRefState(statePath, state)
  })

  if (updated === null) {
    return
  }

  bwrapMountPoints.add(mountPoint)
  registerExitCleanupHandler()
}

function acquireTrackedMountPointReferenceIfPresent(
  mountPoint: string,
): boolean {
  if (bwrapMountPoints.has(mountPoint)) {
    return true
  }

  const acquired = withMountPointStateLock(mountPoint, statePath => {
    const state = readMountPointRefState(statePath)
    if (!state || state.path !== mountPoint) {
      return false
    }

    pruneDeadHolders(state)

    const totalBefore = getTotalHolderCount(state)
    if (totalBefore === 0) {
      try {
        fs.unlinkSync(statePath)
      } catch {
        // Ignore stale state cleanup errors.
      }
      removeMountPointIfPristine(mountPoint)
      return false
    }

    const pidKey = String(process.pid)
    state.holders[pidKey] = (state.holders[pidKey] ?? 0) + 1
    writeMountPointRefState(statePath, state)
    return true
  })

  if (acquired !== true) {
    return false
  }

  bwrapMountPoints.add(mountPoint)
  registerExitCleanupHandler()
  return true
}

function releaseMountPointReference(mountPoint: string): void {
  const released = withMountPointStateLock(mountPoint, statePath => {
    const state = readMountPointRefState(statePath)
    if (!state || state.path !== mountPoint) {
      removeMountPointIfPristine(mountPoint)
      return
    }

    pruneDeadHolders(state)

    const pidKey = String(process.pid)
    const currentCount = state.holders[pidKey] ?? 0
    if (currentCount <= 1) {
      delete state.holders[pidKey]
    } else {
      state.holders[pidKey] = currentCount - 1
    }

    if (getTotalHolderCount(state) === 0) {
      try {
        fs.unlinkSync(statePath)
      } catch {
        // Ignore state cleanup errors.
      }
      removeMountPointIfPristine(mountPoint)
    } else {
      writeMountPointRefState(statePath, state)
    }
  })

  if (released === null) {
    return
  }
}

/**
 * Register cleanup handler for bwrap mount points and temp files.
 */
function registerExitCleanupHandler(): void {
  if (exitHandlerRegistered) {
    return
  }

  process.on('exit', () => {
    cleanupBwrapMountPoints()
    cleanupTempEmptyFiles()
  })

  exitHandlerRegistered = true
}

export function cleanupBwrapMountPoints(): void {
  for (const mountPoint of bwrapMountPoints) {
    releaseMountPointReference(mountPoint)
  }
  bwrapMountPoints.clear()
}

export function cleanupTempEmptyFiles(): void {
  for (const tmpFile of tempEmptyFiles) {
    try {
      fs.unlinkSync(tmpFile)
    } catch {
      // Ignore cleanup errors - temp files are best-effort
    }
  }
  tempEmptyFiles.clear()
}

/**
 * Check if Linux sandbox dependencies are available (synchronous)
 * Returns true if bwrap and socat are installed.
 */
export function hasLinuxSandboxDependenciesSync(): boolean {
  try {
    const bwrapResult = spawnSync('which', ['bwrap'], {
      stdio: 'ignore',
      timeout: 1000,
    })
    const socatResult = spawnSync('which', ['socat'], {
      stdio: 'ignore',
      timeout: 1000,
    })

    return bwrapResult.status === 0 && socatResult.status === 0
  } catch {
    return false
  }
}

/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
export async function initializeLinuxNetworkBridge(
  httpProxyPort: number,
  socksProxyPort: number,
): Promise<LinuxNetworkBridgeContext> {
  const socketId = randomBytes(8).toString('hex')
  const httpSocketPath = join(tmpdir(), `claude-http-${socketId}.sock`)
  const socksSocketPath = join(tmpdir(), `claude-socks-${socketId}.sock`)

  // Start HTTP bridge
  const httpSocatArgs = [
    `UNIX-LISTEN:${httpSocketPath},fork,reuseaddr`,
    `TCP:localhost:${httpProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting HTTP bridge: socat ${httpSocatArgs.join(' ')}`)

  const httpBridgeProcess = spawn('socat', httpSocatArgs, {
    stdio: 'ignore',
  })

  if (!httpBridgeProcess.pid) {
    throw new Error('Failed to start HTTP bridge process')
  }

  // Add error and exit handlers to monitor bridge health
  httpBridgeProcess.on('error', err => {
    logForDebugging(`HTTP bridge process error: ${err}`, { level: 'error' })
  })
  httpBridgeProcess.on('exit', (code, signal) => {
    logForDebugging(
      `HTTP bridge process exited with code ${code}, signal ${signal}`,
      { level: code === 0 ? 'info' : 'error' },
    )
  })

  // Start SOCKS bridge
  const socksSocatArgs = [
    `UNIX-LISTEN:${socksSocketPath},fork,reuseaddr`,
    `TCP:localhost:${socksProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting SOCKS bridge: socat ${socksSocatArgs.join(' ')}`)

  const socksBridgeProcess = spawn('socat', socksSocatArgs, {
    stdio: 'ignore',
  })

  if (!socksBridgeProcess.pid) {
    // Clean up HTTP bridge
    if (httpBridgeProcess.pid) {
      try {
        process.kill(httpBridgeProcess.pid, 'SIGTERM')
      } catch {
        // Ignore errors
      }
    }
    throw new Error('Failed to start SOCKS bridge process')
  }

  // Add error and exit handlers to monitor bridge health
  socksBridgeProcess.on('error', err => {
    logForDebugging(`SOCKS bridge process error: ${err}`, { level: 'error' })
  })
  socksBridgeProcess.on('exit', (code, signal) => {
    logForDebugging(
      `SOCKS bridge process exited with code ${code}, signal ${signal}`,
      { level: code === 0 ? 'info' : 'error' },
    )
  })

  // Wait for both sockets to be ready
  const maxAttempts = 5
  for (let i = 0; i < maxAttempts; i++) {
    if (
      !httpBridgeProcess.pid ||
      httpBridgeProcess.killed ||
      !socksBridgeProcess.pid ||
      socksBridgeProcess.killed
    ) {
      throw new Error('Linux bridge process died unexpectedly')
    }

    try {
      // fs already imported
      if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSocketPath)) {
        logForDebugging(`Linux bridges ready after ${i + 1} attempts`)
        break
      }
    } catch (err) {
      logForDebugging(`Error checking sockets (attempt ${i + 1}): ${err}`, {
        level: 'error',
      })
    }

    if (i === maxAttempts - 1) {
      // Clean up both processes
      if (httpBridgeProcess.pid) {
        try {
          process.kill(httpBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      if (socksBridgeProcess.pid) {
        try {
          process.kill(socksBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      throw new Error(
        `Failed to create bridge sockets after ${maxAttempts} attempts`,
      )
    }

    await new Promise(resolve => setTimeout(resolve, i * 100))
  }

  return {
    httpSocketPath,
    socksSocketPath,
    httpBridgeProcess,
    socksBridgeProcess,
    httpProxyPort,
    socksProxyPort,
  }
}

/**
 * Build the command that runs inside the sandbox.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 */
function buildSandboxCommand(
  httpSocketPath: string,
  socksSocketPath: string,
  userCommand: string,
  shell?: string,
): string {
  // Default to bash for backward compatibility
  const shellPath = shell || 'bash'
  const socatCommands = [
    `socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:${httpSocketPath} >/dev/null 2>&1 &`,
    `socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:${socksSocketPath} >/dev/null 2>&1 &`,
    'trap "kill %1 %2 2>/dev/null; exit" EXIT',
  ]

  const innerScript = [
    ...socatCommands,
    `eval ${shellquote.quote([userCommand])}`,
  ].join('\n')

  return `${shellPath} -c ${shellquote.quote([innerScript])}`
}

/**
 * Generate filesystem bind mount arguments for bwrap
 */
async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  mandatoryDenySearchDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const args: string[] = []
  // fs already imported

  // Determine initial root mount based on write restrictions
  if (writeConfig) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.push('--ro-bind', '/', '/')

    // Collect normalized allowed write paths for later checking
    const allowedWritePaths: string[] = []

    // Allow writes to specific paths
    for (const pathPattern of writeConfig.allowOnly || []) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      logForDebugging(
        `[Sandbox Linux] Processing write path: ${pathPattern} -> ${normalizedPath}`,
      )

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        logForDebugging(`[Sandbox Linux] Skipping /dev path: ${normalizedPath}`)
        continue
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent write path: ${normalizedPath}`,
        )
        continue
      }

      args.push('--bind', normalizedPath, normalizedPath)
      allowedWritePaths.push(normalizedPath)
    }

    // Deny writes within allowed paths (user-specified + mandatory denies)
    const denyPaths = [
      ...(writeConfig.denyWithinAllow || []),
      ...(await linuxGetMandatoryDenyPaths(
        ripgrepConfig,
        mandatoryDenySearchDepth,
        allowGitConfig,
        abortSignal,
      )),
    ]

    for (const pathPattern of denyPaths) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        continue
      }

      if (!fs.existsSync(normalizedPath)) {
        if (hasFileAncestor(normalizedPath)) {
          logForDebugging(
            `[Sandbox Linux] Skipping deny path with file ancestor: ${normalizedPath}`,
          )
          continue
        }

        let ancestorPath = path.dirname(normalizedPath)
        while (ancestorPath !== '/' && !fs.existsSync(ancestorPath)) {
          ancestorPath = path.dirname(ancestorPath)
        }

        const ancestorIsWithinAllowedPath = allowedWritePaths.some(
          allowedPath =>
            ancestorPath.startsWith(allowedPath + '/') ||
            ancestorPath === allowedPath ||
            normalizedPath.startsWith(allowedPath + '/'),
        )

        if (ancestorIsWithinAllowedPath) {
          const firstNonExistent = findFirstNonExistentComponent(normalizedPath)
          if (firstNonExistent !== normalizedPath) {
            const emptyDir = fs.mkdtempSync(
              path.join(tmpdir(), 'claude-empty-'),
            )
            args.push('--ro-bind', emptyDir, firstNonExistent)
            acquireMountPointReference(firstNonExistent)
            logForDebugging(
              `[Sandbox Linux] Mounted empty dir at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          } else {
            args.push('--ro-bind', '/dev/null', firstNonExistent)
            acquireMountPointReference(firstNonExistent)
            logForDebugging(
              `[Sandbox Linux] Mounted /dev/null at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          }
        } else {
          logForDebugging(
            `[Sandbox Linux] Skipping non-existent deny path not within allowed paths: ${normalizedPath}`,
          )
        }
        continue
      }

      // Only add deny binding if this path is within an allowed write path
      // Otherwise it's already read-only from the initial --ro-bind / /
      const isWithinAllowedPath = allowedWritePaths.some(
        allowedPath =>
          normalizedPath.startsWith(allowedPath + '/') ||
          normalizedPath === allowedPath,
      )

      if (isWithinAllowedPath) {
        acquireTrackedMountPointReferenceIfPresent(normalizedPath)

        if (!fs.existsSync(normalizedPath)) {
          const firstNonExistent = findFirstNonExistentComponent(normalizedPath)
          if (firstNonExistent !== normalizedPath) {
            const emptyDir = fs.mkdtempSync(
              path.join(tmpdir(), 'claude-empty-'),
            )
            args.push('--ro-bind', emptyDir, firstNonExistent)
            acquireMountPointReference(firstNonExistent)
            logForDebugging(
              `[Sandbox Linux] TOCTOU fallback: mounted empty dir at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          } else {
            args.push('--ro-bind', '/dev/null', firstNonExistent)
            acquireMountPointReference(firstNonExistent)
            logForDebugging(
              `[Sandbox Linux] TOCTOU fallback: mounted /dev/null at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          }
          continue
        }

        args.push('--ro-bind', normalizedPath, normalizedPath)
      } else {
        logForDebugging(
          `[Sandbox Linux] Skipping deny path not within allowed paths: ${normalizedPath}`,
        )
      }
    }

    for (const pathPattern of writeConfig.allowWithinDeny ?? []) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      if (normalizedPath.startsWith('/dev/')) {
        continue
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent allowWithinDeny write path: ${normalizedPath}`,
        )
        continue
      }

      const isWithinAllowedPath = allowedWritePaths.some(
        allowedPath =>
          normalizedPath.startsWith(allowedPath + '/') ||
          normalizedPath === allowedPath,
      )

      if (!isWithinAllowedPath) {
        logForDebugging(
          `[Sandbox Linux] Skipping allowWithinDeny write path not within allowed paths: ${normalizedPath}`,
        )
        continue
      }

      args.push('--bind', normalizedPath, normalizedPath)
    }
  } else {
    // No write restrictions: Allow all writes
    args.push('--bind', '/', '/')
  }

  // Handle read restrictions by mounting tmpfs over denied paths
  const readDenyPaths = [...(readConfig?.denyOnly || [])]

  // Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
  // SSH is very strict about config file permissions and ownership, and they can
  // appear wrong inside the sandbox causing "Bad owner or permissions" errors
  if (fs.existsSync('/etc/ssh/ssh_config.d')) {
    readDenyPaths.push('/etc/ssh/ssh_config.d')
  }

  for (const pathPattern of readDenyPaths) {
    const normalizedPath = normalizePathForSandbox(pathPattern)
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent read deny path: ${normalizedPath}`,
      )
      continue
    }

    const readDenyStat = fs.statSync(normalizedPath)
    if (readDenyStat.isDirectory()) {
      args.push('--tmpfs', normalizedPath)
    } else {
      // For files, bind /dev/null instead of tmpfs
      args.push('--ro-bind', '/dev/null', normalizedPath)
    }
  }

  for (const pathPattern of readConfig?.allowWithinDeny ?? []) {
    const normalizedPath = normalizePathForSandbox(pathPattern)
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent allowWithinDeny path: ${normalizedPath}`,
      )
      continue
    }

    args.push('--ro-bind', normalizedPath, normalizedPath)
  }

  for (const pathPattern of readConfig?.denyWithinAllow ?? []) {
    const normalizedPath = normalizePathForSandbox(pathPattern)
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent denyWithinAllow path: ${normalizedPath}`,
      )
      continue
    }

    const reDenyStat = fs.statSync(normalizedPath)
    if (reDenyStat.isDirectory()) {
      args.push('--tmpfs', normalizedPath)
      continue
    }

    const tmpFile = path.join(
      tmpdir(),
      `srt-empty-${randomBytes(6).toString('hex')}`,
    )
    fs.writeFileSync(tmpFile, '')
    tempEmptyFiles.add(tmpFile)
    registerExitCleanupHandler()
    args.push('--ro-bind', tmpFile, normalizedPath)
  }

  return args
}

/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * This implementation uses bwrap for filesystem, network, and process isolation.
 *
 * Stage 1: Outer bwrap - Network and filesystem isolation
 *   - Bubblewrap starts with isolated network namespace (--unshare-net)
 *   - Bubblewrap applies PID namespace isolation (--unshare-pid and --proc)
 *   - Filesystem restrictions are applied (read-only mounts, bind mounts, etc.)
 *   - Socat processes start and connect to Unix socket bridges (can use socket(AF_UNIX, ...))
 */
export async function wrapCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<string> {
  const {
    command,
    needsNetworkRestriction,
    httpSocketPath,
    socksSocketPath,
    httpProxyPort,
    socksProxyPort,
    readConfig,
    writeConfig,
    enableWeakerNestedSandbox,
    binShell,
    ripgrepConfig = { command: 'rg' },
    mandatoryDenySearchDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allowGitConfig = false,
    deviceConfig,
    abortSignal,
  } = params

  // Determine if we have restrictions to apply
  // Read: denyOnly pattern - empty array means no restrictions
  // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
  const hasReadRestrictions = Boolean(
    readConfig &&
      (readConfig.denyOnly.length > 0 ||
        (readConfig.allowWithinDeny?.length ?? 0) > 0 ||
        (readConfig.denyWithinAllow?.length ?? 0) > 0),
  )
  const hasWriteRestrictions = writeConfig !== undefined

  // Check if we need any sandboxing
  if (
    !needsNetworkRestriction &&
    !hasReadRestrictions &&
    !hasWriteRestrictions
  ) {
    return command
  }

  const bwrapArgs: string[] = []

  // ========== NETWORK RESTRICTIONS ==========
  if (needsNetworkRestriction) {
    // Always unshare network namespace to isolate network access
    // This removes all network interfaces, effectively blocking all network
    bwrapArgs.push('--unshare-net')

    // If proxy sockets are provided, bind them into the sandbox to allow
    // filtered network access through the proxy. If not provided, network
    // is completely blocked (empty allowedDomains = block all)
    if (httpSocketPath && socksSocketPath) {
      // Verify socket files still exist before trying to bind them
      if (!fs.existsSync(httpSocketPath)) {
        throw new Error(
          `Linux HTTP bridge socket does not exist: ${httpSocketPath}. ` +
            'The bridge process may have died. Try reinitializing the sandbox.',
        )
      }
      if (!fs.existsSync(socksSocketPath)) {
        throw new Error(
          `Linux SOCKS bridge socket does not exist: ${socksSocketPath}. ` +
            'The bridge process may have died. Try reinitializing the sandbox.',
        )
      }

      // Bind both sockets into the sandbox
      bwrapArgs.push('--bind', httpSocketPath, httpSocketPath)
      bwrapArgs.push('--bind', socksSocketPath, socksSocketPath)

      // Add proxy environment variables
      // HTTP_PROXY points to the socat listener inside the sandbox (port 3128)
      // which forwards to the Unix socket that bridges to the host's proxy server
      const proxyEnv = generateProxyEnvVars(3128, 1080)
      bwrapArgs.push(
        ...proxyEnv.flatMap((env: string) => {
          const firstEq = env.indexOf('=')
          const key = env.slice(0, firstEq)
          const value = env.slice(firstEq + 1)
          return ['--setenv', key, value]
        }),
      )

      // Add host proxy port environment variables for debugging/transparency
      if (httpProxyPort !== undefined) {
        bwrapArgs.push(
          '--setenv',
          'CLAUDE_CODE_HOST_HTTP_PROXY_PORT',
          String(httpProxyPort),
        )
      }
      if (socksProxyPort !== undefined) {
        bwrapArgs.push(
          '--setenv',
          'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT',
          String(socksProxyPort),
        )
      }
    }
    // If no sockets provided, network is completely blocked (--unshare-net without proxy)
  }

  // ========== FILESYSTEM RESTRICTIONS ==========
  const fsArgs = await generateFilesystemArgs(
    readConfig,
    writeConfig,
    ripgrepConfig,
    mandatoryDenySearchDepth,
    allowGitConfig,
    abortSignal,
  )
  bwrapArgs.push(...fsArgs)

  // Always create a synthetic /dev for the sandbox. Host accelerator / GPU
  // and other permitted host device nodes are rebound afterwards so filesystem
  // restrictions remain the main boundary while device exposure stays policy-driven.
  bwrapArgs.push('--dev', '/dev')
  appendLinuxHostDevicePassthroughArgs(bwrapArgs, deviceConfig)

  // ========== PID NAMESPACE ISOLATION ==========
  bwrapArgs.push('--unshare-pid')
  if (!enableWeakerNestedSandbox) {
    bwrapArgs.push('--proc', '/proc')
  }

  // ========== COMMAND ==========
  const shellName = binShell || 'bash'
  const shellPathResult = spawnSync('which', [shellName], {
    encoding: 'utf8',
  })
  if (shellPathResult.status !== 0) {
    throw new Error(`Shell '${shellName}' not found in PATH`)
  }
  const shell = shellPathResult.stdout.trim()
  bwrapArgs.push('--', shell, '-c')

  if (needsNetworkRestriction && httpSocketPath && socksSocketPath) {
    const sandboxCommand = buildSandboxCommand(
      httpSocketPath,
      socksSocketPath,
      command,
      shell,
    )
    bwrapArgs.push(sandboxCommand)
  } else {
    bwrapArgs.push(command)
  }

  const wrappedCommand = shellquote.quote(['bwrap', ...bwrapArgs])

  const restrictions = []
  if (needsNetworkRestriction) restrictions.push('network')
  if (hasReadRestrictions || hasWriteRestrictions) {
    restrictions.push('filesystem')
  }

  logForDebugging(
    `[Sandbox Linux] Wrapped command with bwrap (${restrictions.join(', ')} restrictions)`,
  )

  return wrappedCommand
}
