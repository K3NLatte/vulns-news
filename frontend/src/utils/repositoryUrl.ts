import { MAX_URL_LENGTH, isWellFormedText } from './publicUrl'
import { hasUnsafeCharacters } from './inputText'
import type { RepositoryUrlResult } from '../types/feed'

/** Validates input only; this does not establish that a repository is public or exists. */
export function parseRepositoryUrl(input: unknown): RepositoryUrlResult {
  const invalid = (message: string): RepositoryUrlResult => ({ ok: false, message })
  if (typeof input !== 'string' || input.length > MAX_URL_LENGTH || !isWellFormedText(input) || hasUnsafeCharacters(input) || /[\r\n\t]/u.test(input)) return invalid('2,048文字以内の正しいリポジトリURLを入力してください。')
  const value = input.trim()

  if (!value) return invalid('公開GitHubリポジトリのURLを入力してください。')
  if (/[\s\\%?#]/u.test(value)) {
    return invalid('クエリ・フラグメント・エンコードを含まないリポジトリURLを入力してください。')
  }

  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return invalid('https://github.com/所有者/リポジトリ の形式で入力してください。')
  }

  if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com') {
    return invalid('現在は https://github.com/ で始まるURLに対応しています。')
  }
  if (parsed.username || parsed.password || parsed.port || /^https:\/\/[^/]*@/iu.test(value)) {
    return invalid('認証情報や独自のポート番号を含まないURLを入力してください。')
  }

  // Validate the original path too: URL() normalizes /./ and /../ before inspection.
  const originalPath = value.match(/^https:\/\/[^/]+(\/.*)$/iu)?.[1]
  const path = originalPath?.match(/^\/([a-z\d](?:[a-z\d-]*[a-z\d])?)\/([a-z\d_.-]+)\/?$/iu)
  if (!path) {
    return invalid('ファイルやブランチではなく、リポジトリのトップページのURLを入力してください。')
  }

  const owner = path[1]!
  const repository = path[2]!.replace(/\.git$/iu, '')
  if (!repository || repository === '.' || repository === '..') {
    return invalid('リポジトリ名を含むURLを入力してください。')
  }

  const reservedOwners = new Set(['features', 'topics', 'collections', 'marketplace', 'settings', 'login', 'signup', 'orgs', 'users', 'search', 'pulls', 'issues', 'notifications', 'new', 'sponsors', 'explore', 'advisories'])
  if (owner.length > 39 || repository.length > 100 || reservedOwners.has(owner.toLowerCase())) {
    return invalid('有効な所有者名（39文字以内）とリポジトリ名（100文字以内）を入力してください。')
  }
  const label = `${owner}/${repository}`
  return { ok: true, url: `https://github.com/${label.toLowerCase()}`, label }
}
