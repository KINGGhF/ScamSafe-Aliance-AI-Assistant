export type Priority = 'P1 — Immediate' | 'P2 — Priority' | 'P3 — Standard' | 'Priority requires clarification'
export type ReviewState = 'pending' | 'accepted' | 'modified' | 'rejected'
export type RecommendationKind = 'Primary Recommendation' | 'Additional Recommendation' | 'Necessary Parallel Action' | 'Follow-up / Reporting Suggestion'
export type Fact = { label: string; value: string }
export type Vulnerability = { title: string; evidence: string; suggestion: string }
export type Recommendation = { id: string; kind: RecommendationKind; organisation: string; team: string; action: string; reason: string; condition?: string }
export type Decision = { state: ReviewState; editedAction: string; notes: string }
export type Analysis = {
  caseId: string; originalNarrative: string; workerClarifications: string; summary: string; caseTypes: string[]; reportedFacts: Fact[]
  priority: Priority; interimAction: string; vulnerabilityIndicators: Vulnerability[]; missingInfo: string[]; conflicts: string[]
  pendingVerification: string[]; clarifyingQuestions: string[]; recommendations: Recommendation[]; reviewDecisions: Record<string, Decision>
}
