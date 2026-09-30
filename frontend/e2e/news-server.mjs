import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Exercise the shipped CLI and restore path without touching the operator's .local/news.
const temporary = mkdtempSync(join(tmpdir(), 'vulns-news-e2e-'))
const binary = join(temporary, process.platform === 'win32' ? 'news-server.exe' : 'news-server')
const data = join(temporary, 'data')
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${command} exited with ${result.status}`)
}
process.on('exit', () => rmSync(temporary, { recursive: true, force: true }))
run('go', ['build', '-o', binary, '../cmd/news-server'])
run(binary, ['-data', data, '-model=',
  '-import-scan', '../cmd/repo-analyze/testdata/pre-citation-fix/scan.json',
  '-import-analysis', '../cmd/repo-analyze/testdata/pre-citation-fix/analysis.json', '-import-only'])
const server = spawn(binary, ['-addr', '127.0.0.1:4176', '-data', data, '-frontend', 'dist', '-model='], { stdio: 'inherit' })
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.kill(signal))
server.on('error', error => { console.error(error); process.exitCode = 1 })
server.on('exit', code => { process.exitCode = code ?? 1 })
