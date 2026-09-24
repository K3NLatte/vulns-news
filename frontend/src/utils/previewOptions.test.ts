import { describe, expect, it } from 'vitest'
import { readPreviewOptions } from './previewOptions'

describe('development preview URLs', () => {
  it.each(['loading', 'empty', 'error'])('ignores %s and all preview switches in a production build', scenario => {
    expect(readPreviewOptions(`?scenario=${scenario}&analysis=completed&view=mvp`, false)).toEqual({
      fullFeatures: true, preview: 'ready', analysisStage: null,
    })
  })
  it('keeps explicit development fixtures available', () => {
    expect(readPreviewOptions('?scenario=empty&analysis=failed&view=mvp', true)).toEqual({
      fullFeatures: false, preview: 'empty', analysisStage: 'failed',
    })
  })
  it('does not turn an unknown analysis parameter into a preview state', () => {
    expect(readPreviewOptions('?analysis=unknown', true).analysisStage).toBeNull()
  })
})
