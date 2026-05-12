import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  formatEnvVarsForShellExport,
  generateProxyEnvVars,
} from '../../src/sandbox/sandbox-utils.js'

describe('generateProxyEnvVars', () => {
  it('configures git ssh proxying for SOCKS on all platforms', () => {
    const envVars = generateProxyEnvVars(undefined, 1080)

    const gitSsh = envVars.find(env => env.startsWith('GIT_SSH_COMMAND='))
    const gitSshValue = gitSsh?.slice('GIT_SSH_COMMAND='.length)

    expect(gitSsh).toBeDefined()
    expect(gitSshValue).toBe(
      "ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/srt-ssh-known-hosts",
    )
    expect(envVars).toContain('SSH_ASKPASS_REQUIRE=never')
    expect(envVars.some(env => env.startsWith('GIT_CONFIG_'))).toBe(false)
  })

  it('shell-exports GIT_SSH_COMMAND without breaking sh execution', () => {
    if (spawnSync('which', ['ssh'], { stdio: 'ignore' }).status !== 0) {
      return
    }

    const envVars = generateProxyEnvVars(undefined, 1080)
    const exportCommand = formatEnvVarsForShellExport(envVars)
    const result = spawnSync(
      '/bin/sh',
      [
        '-lc',
        `${exportCommand}; eval "$GIT_SSH_COMMAND -G github.com >/dev/null"`,
      ],
      {
        encoding: 'utf8',
      },
    )

    expect(result.status).toBe(0)
    expect(result.stderr).not.toContain('not found')
  })
})
