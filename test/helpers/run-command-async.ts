import { spawn } from 'node:child_process'

export interface AsyncCommandResult {
  status: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
}

export async function runCommandAsync(
  command: string,
  options: {
    cwd?: string
    timeoutMs?: number
  } = {},
): Promise<AsyncCommandResult> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, {
      shell: true,
      cwd: options.cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    let forceKillTimer: NodeJS.Timeout | undefined

    const timeoutTimer =
      options.timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            child.kill('SIGTERM')
            forceKillTimer = setTimeout(() => {
              child.kill('SIGKILL')
            }, 1000)
          }, options.timeoutMs)

    child.stdout?.on('data', chunk => {
      stdout += chunk.toString()
    })

    child.stderr?.on('data', chunk => {
      stderr += chunk.toString()
    })

    child.on('error', error => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer)
      }
      if (forceKillTimer) {
        clearTimeout(forceKillTimer)
      }
      reject(error)
    })

    child.on('close', (code, signal) => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer)
      }
      if (forceKillTimer) {
        clearTimeout(forceKillTimer)
      }
      resolve({
        status: code,
        signal,
        stdout,
        stderr,
      })
    })
  })
}
