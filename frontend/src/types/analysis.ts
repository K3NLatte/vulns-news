export type AnalysisStage =
  | 'queued'
  | 'profiling'
  | 'matching'
  | 'screening'
  | 'analyzing'
  | 'completed'
  | 'failed'

/** 解析状況の画面表示用モデル。バックエンドのAPI契約ではない。 */
export interface AnalysisSnapshot {
  stage: AnalysisStage
  /** 現在の段階で処理済みの件数。件数は判明している場合だけ渡す。 */
  processed?: number
  /** 現在の段階で処理する対象の総数。 */
  total?: number
  /** 詳細分析を完了し、分析済みフィードで閲覧できる件数。 */
  confirmedCount?: number
  /** 関連性が未確定のフィードで閲覧できる件数。 */
  pendingCount?: number
  /** 件数を渡さない場合でも、閲覧できる結果があるかを示せる。 */
  hasAvailableResults?: boolean
  errorMessage?: string
}