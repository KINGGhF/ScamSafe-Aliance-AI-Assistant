import { describe, expect, it } from 'vitest'
import { analysisMode, validateModelShape } from './server.mjs'

const validExtraction = {
  summary: 'A person reported a suspicious contact.',
  safetyAssessment: { status: 'not_mentioned', evidence: [] },
  caseTypes: [],
  facts: [],
  missingInformation: [],
  conflicts: [],
  vulnerabilityIndicators: [],
  riskSignals: [],
}

describe('Model server safeguards', () => {
  it('defaults to Gemini per Rules v4.2 and supports explicitly selected OpenAI', () => {
    expect(analysisMode({})).toBe('demo')
    expect(analysisMode({ GEMINI_API_KEY: 'configured' })).toBe('gemini')
    expect(analysisMode({ OPENAI_API_KEY: '  ' })).toBe('demo')
    expect(analysisMode({ AI_PROVIDER: 'openai', OPENAI_API_KEY: 'configured' })).toBe('openai')
  })

  it('accepts the extraction contract and rejects unsupported fields', () => {
    expect(validateModelShape(validExtraction)).toBe(true)
    expect(validateModelShape({ ...validExtraction, priority: 'P1 — Immediate' })).toBe(false)
    expect(validateModelShape({ ...validExtraction, safetyAssessment: { status: 'current_danger', evidence: [null] } })).toBe(false)
  })
})
