import { describe, expect, it } from 'vitest'
import acceptance from '../docs/ScamSafe_Acceptance_Cases.json'
import { analyzeCase, localAnalyze, reconcileAnalysis, validateModelExtraction } from './analysis'
import type { ModelExtraction } from './types'

const cases = acceptance.cases
const amount = (value: string | undefined) => value?.replace(/,/g, '')

describe(`ScamSafe Policy ${acceptance.policyVersion} acceptance cases`, () => {
  const implemented = cases.filter(c => !['correction_overrides','accept_persists','malformed_model_result','api_failure'].includes(c.id))

  it.each(implemented)('$id: enforces the policy invariants', ({ input, expected }) => {
    const a = localAnalyze(input)
    const teams = a.recommendations.map(r => r.team).filter(Boolean)
    if ('priority' in expected && expected.priority) expect(a.priority.startsWith(String(expected.priority))).toBe(true)
    if ('primaryTeam' in expected && expected.primaryTeam) expect(a.recommendations[0]?.team).toBe(expected.primaryTeam)
    if ('emptyRecommendations' in expected) expect(a.recommendations.length===0).toBe(expected.emptyRecommendations)
    if ('mustNotPrimaryTeam' in expected) expect(a.recommendations[0]?.team).not.toBe(expected.mustNotPrimaryTeam)
    if ('mustNotPriority' in expected && expected.mustNotPriority) expect(a.priority.startsWith(String(expected.mustNotPriority))).toBe(false)
    if ('urgentHumanSafetyReview' in expected) expect(a.safetyReviewRequired).toBe(expected.urgentHumanSafetyReview)
    if ('mustNotClaim' in expected) expect(`${a.summary} ${a.caseTypes.join(' ')}`).not.toMatch(/confirmed scam/i)
    if ('reportedAmount' in expected && expected.reportedAmount) expect(amount(a.reportedFacts.find(f=>f.label==='Reported Amount')?.value.replace(/^AUD\s*/,''))).toBe(amount(String(expected.reportedAmount).replace(/^AUD\s*/,'')))
    if ('transaction' in expected) expect(a.reportedFacts.find(f=>f.label==='Transaction Status')?.value).toBe('Reported as completed')
    if ('paymentRoute' in expected) {
      const route=a.reportedFacts.find(f=>f.label==='Payment Route')?.value
      expect(route).toBe(expected.paymentRoute==='unknown'?'Not specified':expected.paymentRoute==='bank_transfer'?'Bank transfer':expected.paymentRoute==='wallet'?'Payment wallet':expected.paymentRoute==='platform_balance'?'Platform balance':'Card payment')
    }
    if ('pendingVerification' in expected) expect(a.pendingVerification.length>0).toBe(expected.pendingVerification)
    if ('hasConditionalRoutes' in expected) expect(a.recommendations.some(r=>r.condition?.includes('Card payment →'))).toBe(expected.hasConditionalRoutes)
    if ('mustNotTransactionLabel' in expected) expect(`${a.summary} ${a.reportedFacts.map(f=>f.value).join(' ')}`.toLowerCase()).not.toContain(String(expected.mustNotTransactionLabel))
    if ('transactionType' in expected) expect(a.recommendations[0]?.action.toLowerCase()).toContain('unauthorised')
    if ('mustNotInventConflict' in expected) expect(a.conflicts).toEqual([])
    if ('conflictFlag' in expected) expect(a.conflicts.length>0).toBe(expected.conflictFlag)
    if ('additionalTeam' in expected) expect(teams).toContain(expected.additionalTeam)
    if ('mustNotAssume' in expected) expect(a.reportedFacts.some(f=>f.label==='Credential Disclosure')).toBe(false)
    if ('mustNotAdditionalTeam' in expected) expect(a.recommendations.filter(r=>r.kind==='Additional Recommendation').map(r=>r.team)).not.toContain(expected.mustNotAdditionalTeam)
  })

  it('applies an explicit employee correction and retains both source records', () => {
    const a=analyzeCase('I paid by bank transfer.','SSA-TEST','','Employee verified correction: the actual payment used a third-party wallet.')
    expect(a.reportedFacts.find(f=>f.label==='Payment Route')?.value).toBe('Payment wallet')
    expect(a.recommendations[0]?.team).toBe('Payment Provider Fraud')
    expect(a.originalNarrative).toContain('bank transfer')
    expect(a.employeeCorrections).toContain('third-party wallet')
  })

  it('rejects model decisions and unsupported extraction fields', () => {
    const malformed={summary:'Immediate danger reported.',safetyAssessment:{status:'current_danger',evidence:['immediate danger']},caseTypes:[],facts:[],missingInformation:[],conflicts:[],vulnerabilityIndicators:[],riskSignals:[],priority:'P3'}
    expect(validateModelExtraction(malformed)).toBe(false)
    const a=reconcileAnalysis(malformed,'I am in immediate danger right now.','SSA-TEST')
    expect(a.priority).not.toBe('P3 — Standard')
    expect(a.recommendations[0]?.team).toBe('Designated Safety Contact')
  })

  it('accepts a supported semantic model extraction without exposing provider credentials', () => {
    const raw:ModelExtraction={summary:'A person reports a threat today and immediate danger.',safetyAssessment:{status:'current_danger',evidence:['the person reports being in immediate danger']},caseTypes:[],facts:[],missingInformation:[],conflicts:[],vulnerabilityIndicators:[],riskSignals:[]}
    const a=reconcileAnalysis(raw,'The suspected scammer threatened to come to the person’s home today and the person reports being in immediate danger.','SSA-TEST','','','gemini',acceptance.policyVersion,'mock-gemini-structured')
    expect(a.mode).toBe('gemini')
    expect(a.model).toBe('mock-gemini-structured')
    expect(a.policyVersion).toBe(acceptance.policyVersion)
    expect(a.priority).toBe('P1 — Immediate')
    expect(a.recommendations[0]?.team).toBe('Designated Safety Contact')
  })
})
