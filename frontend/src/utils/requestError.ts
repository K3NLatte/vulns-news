/** Only these public messages may cross the data adapter boundary. */
export type RequestFailure = 'network' | 'timeout' | 'unauthorized' | 'forbidden' | 'limited' | 'server' | 'contract'
export class RequestError extends Error {
  constructor(readonly kind: RequestFailure) {
    super(kind)
  }
}
export function requestErrorMessage(cause: unknown): string {
  const kind = cause instanceof RequestError ? cause.kind : 'network'
  const messages: Record<RequestFailure, string> = {
    network: '通信できませんでした。接続を確認して再試行してください。',
    timeout: '読み込みに時間がかかっています。再試行してください。',
    unauthorized: 'ログインが必要です。ログインして再試行してください。',
    forbidden: 'この情報を表示する権限がありません。',
    limited: 'リクエストが集中しています。時間をおいて再試行してください。',
    server: 'サービスで問題が発生しています。時間をおいて再試行してください。',
    contract: 'フィードのデータ形式を確認できませんでした。再試行してください。',
  }
  return messages[kind]
}
