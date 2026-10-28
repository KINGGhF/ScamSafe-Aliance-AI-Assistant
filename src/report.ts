import type { Analysis, Decision } from './types'

const sourceName = (origin: string) => ({case_intake:'Reported in Case Intake',gemini_extracted:'Gemini extraction (employee review required)',openai_extracted:'OpenAI extraction (employee review required)',rule_derived:'Deterministic rule',employee_correction:'Employee correction',demo_extracted:'Limited Demo Mode extraction'} as Record<string,string>)[origin] ?? origin
export function buildReport(analysis: Analysis, decisions: Record<string, Decision>): string {
  const lines = [
    '# Synthetic Case Report — Not Sent', `Case ID: ${analysis.caseId}`, `Generated: ${new Date().toLocaleString()}`, `Analysis mode: ${analysis.mode==='gemini'?'Gemini Real AI':analysis.mode==='openai'?'OpenAI Real AI':'Limited Demo Mode'}`,
    `Immediate human safety review required: ${analysis.safetyReviewRequired?'Yes — '+analysis.safetyReviewMessage:'No unresolved safety cue flagged.'}`,
    '', '## Case Summary', analysis.summary, `Source: ${sourceName(analysis.summaryOrigin)}`,
    '', '## Reported and extracted case facts', ...analysis.reportedFacts.map(f=>`- ${f.label}: ${f.value} — ${sourceName(f.origin)}${f.evidence?` (evidence: “${f.evidence}”)`:''}`),
    '', '## Rule-derived decisions', `Priority: ${analysis.priority}`, `Rule: ${analysis.priorityRule}`, `Evidence: ${analysis.priorityEvidence.join(' ')||'No immediate or priority risk evidence identified.'}`, analysis.interimAction,
    '', '## Outstanding information', `Missing Information: ${analysis.missingInfo.join(' ')||'None identified.'}`, `Conflict Flag: ${analysis.conflicts.join(' ')||'None identified.'}`, `Pending Verification: ${analysis.pendingVerification.join(' ')||'None.'}`, `Questions: ${analysis.clarifyingQuestions.join(' ')||'None.'}`,
    '', '## Possible support needs', ...(analysis.vulnerabilityIndicators.length?analysis.vulnerabilityIndicators.map(v=>`- ${v.title}: ${v.evidence} — ${v.suggestion} [${sourceName(v.origin)}]`):['- No qualifying support need identified from the available information.']),
    '', '## Employee input', `Original Case Intake: ${analysis.originalNarrative||'None provided.'}`, `Employee clarification: ${analysis.workerClarifications||'None added.'}`, `Employee correction: ${analysis.employeeCorrections||'None added.'}`,
    '', '## Recommendations and employee decisions'
  ]
  for(const r of analysis.recommendations){
    const d=decisions[r.id]??{state:'pending',editedAction:'',editedTeam:'',notes:''}
    lines.push(`### ${r.kind}`, `Proposed organisation: ${r.organisation??'Pending clarification'}`, `Proposed receiving department: ${d.editedTeam||r.team||'Pending clarification'}`, `Routing status: ${r.routingStatus==='pending_clarification'?'Pending employee clarification':'Proposed'}`, `Employee decision: ${d.state}`, `Original recommendation: ${r.action}`, `Original justification: ${r.reason}`, ...(d.editedAction?[`Employee-modified action: ${d.editedAction}`]:[]), `Current proposed action: ${d.editedAction||r.action}`, ...(r.condition?[`Conditional routes: ${r.condition}`]:[]), ...(d.notes?[`Employee comment: ${d.notes}`]:[]),'')
  }
  lines.push('Human review boundary: recommendations are proposals only. No message, transfer, referral, freeze, account change, or external operation has been performed.')
  return lines.join('\n')
}
