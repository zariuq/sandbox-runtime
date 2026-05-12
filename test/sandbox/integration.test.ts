import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { runCommandAsync } from '../helpers/run-command-async.js'

function skipIfNotLinux(): boolean {
  return getPlatform() !== 'linux'
}

describe('Network allowlist integration', () => {
  const TEST_DIR = join(process.cwd(), '.sandbox-test-empty-domains')

  beforeAll(async () => {
    if (skipIfNotLinux()) {
      return
    }

    if (!existsSync(TEST_DIR)) {
      mkdirSync(TEST_DIR, { recursive: true })
    }
  })

  afterAll(async () => {
    if (skipIfNotLinux()) {
      return
    }

    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }

    await SandboxManager.reset()
  })

  describe('Network blocked with empty allowedDomains', () => {
    beforeAll(async () => {
      if (skipIfNotLinux()) {
        return
      }

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [TEST_DIR],
          denyWrite: [],
        },
      })
    })

    it('should block all HTTP requests when allowedDomains is empty', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 2 --connect-timeout 2 http://example.com 2>&1 || echo "network_failed"',
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      const output = (result.stdout + result.stderr).toLowerCase()
      const networkBlocked =
        output.includes('network_failed') ||
        output.includes("couldn't connect") ||
        output.includes('connection refused') ||
        output.includes('network is unreachable') ||
        output.includes('name or service not known') ||
        output.includes('timed out') ||
        output.includes('connection timed out') ||
        result.status !== 0

      expect(networkBlocked).toBe(true)
      expect(output).not.toContain('example domain')
      expect(output).not.toContain('<!doctype')
    })

    it('should block all HTTPS requests when allowedDomains is empty', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 2 --connect-timeout 2 https://example.com 2>&1 || echo "network_failed"',
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      const output = (result.stdout + result.stderr).toLowerCase()
      const networkBlocked =
        output.includes('network_failed') ||
        output.includes("couldn't connect") ||
        output.includes('connection refused') ||
        output.includes('network is unreachable') ||
        output.includes('name or service not known') ||
        output.includes('timed out') ||
        result.status !== 0

      expect(networkBlocked).toBe(true)
    })

    it('should block DNS lookups when allowedDomains is empty', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await SandboxManager.wrapWithSandbox(
        'host example.com 2>&1 || nslookup example.com 2>&1 || echo "dns_failed"',
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      const output = (result.stdout + result.stderr).toLowerCase()
      const dnsBlocked =
        output.includes('dns_failed') ||
        output.includes('connection timed out') ||
        output.includes('no servers could be reached') ||
        output.includes('network is unreachable') ||
        output.includes('name or service not known') ||
        output.includes('temporary failure') ||
        result.status !== 0

      expect(dnsBlocked).toBe(true)
    })

    it('should block wget when allowedDomains is empty', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await SandboxManager.wrapWithSandbox(
        'wget -q --timeout=2 -O - http://example.com 2>&1 || echo "wget_failed"',
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      const output = (result.stdout + result.stderr).toLowerCase()
      const wgetBlocked =
        output.includes('wget_failed') ||
        output.includes('failed') ||
        output.includes('network is unreachable') ||
        output.includes('unable to resolve') ||
        result.status !== 0

      expect(wgetBlocked).toBe(true)
    })

    it('should allow local filesystem operations when network is blocked', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const testFile = join(TEST_DIR, 'network-blocked-test.txt')
      const testContent = 'test content with network blocked'

      const command = await SandboxManager.wrapWithSandbox(
        `echo "${testContent}" > ${testFile} && cat ${testFile}`,
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        cwd: TEST_DIR,
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain(testContent)

      if (existsSync(testFile)) {
        unlinkSync(testFile)
      }
    })
  })

  describe('Network allowed with specific domains', () => {
    beforeAll(async () => {
      if (skipIfNotLinux()) {
        return
      }

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [TEST_DIR],
          denyWrite: [],
        },
      })
    })

    it('should allow HTTP to explicitly allowed domain', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 5 http://example.com 2>&1',
      )

      const result = await runCommandAsync(command, {
        timeoutMs: 10000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('Example Domain')
    })

    it('should block HTTP to non-allowed domain', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 2 http://anthropic.com 2>&1',
      )

      const result = await runCommandAsync(command, {
        timeoutMs: 5000,
      })

      expect(result.stdout.toLowerCase()).toContain(
        'blocked by network allowlist',
      )
    })
  })

  describe('Contrast: empty vs undefined network config', () => {
    it('empty allowedDomains should block network', async () => {
      if (skipIfNotLinux()) {
        return
      }

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [TEST_DIR],
          denyWrite: [],
        },
      })

      const command = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 2 http://example.com 2>&1 || echo "blocked"',
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      const output = (result.stdout + result.stderr).toLowerCase()
      const isBlocked =
        output.includes('blocked') ||
        output.includes("couldn't connect") ||
        output.includes('network is unreachable') ||
        result.status !== 0

      expect(isBlocked).toBe(true)
      expect(output).not.toContain('example domain')
    })
  })
})
