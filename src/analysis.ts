import type { Analysis, CaseType, Fact, FactOrigin, ModelExtraction, OrganizationCategory, Recommendation, Vulnerability } from './types'

export const fixtures = [
  ['Suspicious store + card debit', 'A person found an online store, entered card information and made a card payment of AUD 280. They received no order confirmation and cannot use their banking app.'],
  ['Recent bank transfer', 'A person transferred AUD 1,250 yesterday to a suspected scam recipient after a phone call. They have not contacted the bank and protection is unknown.'],
  ['Suspicious SMS, no loss', 'A person received a suspicious SMS with a link. They did not click it, pay, or provide credentials.'],
  ['Identity document disclosed', 'A person shared a photo of their driver licence with a website they now suspect was not legitimate. No payment is reported.'],
  ['Ambiguous payment channel', 'A person reports paying AUD 90 to a suspicious seller but cannot say whether it was a bank transfer, card, wallet, or platform balance.'],
  ['Contradictory amount', 'The person reported a payment of AUD 500 and later reported AUD 50 for the same payment.'],
  ['Immediate safety concern', 'The suspected scammer threatened to come to the person’s home today and the person reports being in immediate danger.'],
] as const

const id = () => `SSA-${new Date().getFullYear()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`
const clean = (s: string) => s.replace(/\s+/g, ' ').trim()
const grounded = (source: string, evidence: string) => Boolean(evidence.trim()) && clean(source).toLocaleLowerCase().includes(clean(evidence).toLocaleLowerCase())
const exactKeys = (value: unknown, keys: string[]) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(k => keys.includes(k)) && keys.every(k => k in (value as object))
const questionSafe = (s: string) => s.trim().endsWith('?') && !/password|passcode|one.time|otp|cvv|cvc|full card number|account number/i.test(s)

export function validateModelExtraction(value: unknown): value is ModelExtraction {
  if (!exactKeys(value, ['summary','safetyAssessment','caseTypes','facts','missingInformation','conflicts','vulnerabilityIndicators','riskSignals'])) return false
  const x = value as ModelExtraction
  const arrays = [x.caseTypes, x.facts, x.missingInformation, x.conflicts, x.vulnerabilityIndicators, x.riskSignals]
  if (typeof x.summary !== 'string' || x.summary.length > 900 || arrays.some(a => !Array.isArray(a)) || !exactKeys(x.safetyAssessment,['status','evidence']) || !['current_danger','no_current_danger','uncertain','not_mentioned'].includes(x.safetyAssessment.status) || !Array.isArray(x.safetyAssessment.evidence) || !x.safetyAssessment.evidence.every(e=>typeof e==='string')) return false
  if (x.caseTypes.some(v => !exactKeys(v,['value','evidence']) || !['Suspicious scam contact','Suspected Financial Loss','Possible identity or account credential disclosure'].includes(v.value) || typeof v.evidence !== 'string')) return false
  const factKeys = ['payment_route','transaction_status','amount','contact_channel','credential_disclosure','account_control','authorization','institution_contact','protective_action']
  if (x.facts.some(v => !exactKeys(v,['key','value','evidence','certainty']) || !factKeys.includes(v.key) || typeof v.value !== 'string' || typeof v.evidence !== 'string' || !['reported','possible','unclear'].includes(v.certainty))) return false
  const missingKeys = ['payment_route','transaction_status','institution_contact','protective_action','authorization','credential_type','current_account_access','contact_channel','other']
  if (x.missingInformation.some(v => !exactKeys(v,['key','reason','question']) || !missingKeys.includes(v.key) || typeof v.reason !== 'string' || typeof v.question !== 'string' || !questionSafe(v.question))) return false
  const conflictKeys = ['payment_route','amount','transaction_status','authorization','identity_or_credentials','contact_channel','other']
  if (x.conflicts.some(v => !exactKeys(v,['topic','statements','evidence','explanation']) || !conflictKeys.includes(v.topic) || !Array.isArray(v.statements) || !Array.isArray(v.evidence) || v.statements.length < 2 || !v.statements.every(s=>typeof s==='string') || !v.evidence.every(e=>typeof e==='string') || typeof v.explanation !== 'string')) return false
  const vulnKeys = ['severe_emotional_distress','language_barrier','digital_access','accessibility','essential_needs']
  if (x.vulnerabilityIndicators.some(v => !exactKeys(v,['kind','evidence']) || !vulnKeys.includes(v.kind) || typeof v.evidence !== 'string')) return false
  const riskKeys = ['imminent_payment','recent_payment_unprotected','ongoing_unauthorised_debits','credentials_disclosed_unprotected','account_control_lost','immediate_physical_danger','immediate_self_harm']
  return !x.riskSignals.some(v => !exactKeys(v,['kind','evidence']) || !riskKeys.includes(v.kind) || typeof v.evidence !== 'string')
}

type Route = 'bank_transfer' | 'card' | 'wallet' | 'platform_balance' | 'unknown' | 'none'
const routeEvidence = (text: string): Route[] => {
  const t = text.toLowerCase(); const out: Route[] = []
  if (/\b(bank transfer|wire transfer|transfer(?:red)? from (?:my|the) bank account|bank account transfer)\b|银行转账|银行账户转出/.test(t)) out.push('bank_transfer')
  if (/\b(card payment|card charge|credit card|debit card|paid by card|using (?:a|my|the) card)\b|银行卡扣款|刷卡|卡消费/.test(t)) out.push('card')
  if (/\b(payment wallet|third.party wallet|paid through (?:a|my|the) wallet|wallet payment|payment provider wallet)\b|第三方钱包|钱包付款|钱包余额/.test(t)) out.push('wallet')
  if (/\b(platform balance|in.platform balance|site balance|platform.held balance)\b|平台余额|站内余额/.test(t)) out.push('platform_balance')
  return [...new Set(out)]
}
const money = (text: string) => [...text.matchAll(/(?:\bAUD\s*|A\$\s*|\$\s*)([\d,]+(?:\.\d+)?)(?![\d,])|\b([\d,]+(?:\.\d+)?)\s*(?:AUD|Australian dollars?)\b/gi)].map(m => ({ value: Number((m[1] ?? m[2] ?? '').replace(/,/g,'')), raw: m[0] })).filter(m=>Number.isFinite(m.value))
const hasAction = (s: string) => /\b(transferred|sent|paid|payment went through|charged|debited|deducted|made a payment|completed (?:a )?(?:bank )?transfer|completed (?:a )?payment)\b|已转账|完成转账|扣款/.test(s.toLowerCase())
const deniedPayment = (s: string) => /\b(did not|didn't|have not|haven't|has not|hasn't)\s+(?:send|sent|transfer|transferred|pay|paid)|\bno payment (?:was )?(?:made|sent)|还没转账|没有转账|未转账|没有付款/.test(s.toLowerCase())
const explicitlyNoCurrentSafety = (sentence: string) => /\b(?:not suicidal|not in immediate danger|not in danger right now|no current (?:threat|danger)|there is no current (?:threat|danger)|no longer in danger|was threatened last year.{0,60}(?:no current|not currently)|threatened last year.{0,60}(?:no current|not currently))\b/i.test(sentence) || /不再有危险|目前没有危险|现在没有危险|没有当前威胁/.test(sentence)
const futureHypotheticalSafety = (sentence: string) => /\b(?:worried|afraid|concerned)\b.{0,60}\b(?:may|might|could|possibly)\b.{0,45}\b(?:threaten|hurt|harm|attack)\b.{0,45}\b(?:future|someday|one day|in the future|later)\b/i.test(sentence) || /担心.{0,18}(?:将来|以后|未来).{0,14}(?:威胁|伤害|打)/.test(sentence)
const historicalSafetyOnly = (sentence: string) => /\b(?:was|were) threatened\b.{0,45}\b(?:last year|years ago|last month|in the past)\b/i.test(sentence) && !/\b(?:still|again|now|today|currently|ongoing|continues?)\b/i.test(sentence)
const immediateSafety = (s: string) => s.split(/[.!?。！？\n;]+/).some(sentence=>{
  const t=sentence.toLowerCase().trim()
  if(!t||explicitlyNoCurrentSafety(t)||futureHypotheticalSafety(t)||historicalSafetyOnly(t)) return false
  const selfHarm=/\b(?:i am|i'm|i have|i've)\s+(?:(?:going to|planning to|plan to|thinking of|considering)\s+)?(?:hurt|harm|kill)\s+myself\b|\b(?:i am|i'm) (?:at )?(?:immediate|current) risk of self.harm\b|\bimmediate thoughts? of self.harm\b/.test(t)
  const directDanger=/\b(?:i am|i'm|they are|the person is|the person reports being|reports being|i believe i am)\s+(?:in )?(?:immediate|direct|current) danger\b|\bimmediate physical danger\b/.test(t)
  const imminentThreat=/\b(?:scammer|suspected scammer|someone|a person|the person|they|he|she)\b.{0,55}\b(?:is coming|will come|is on the way|threatened to come|threatened to come over|is threatening to come)\b.{0,55}\b(?:my|their|the person's|the persons|his|her)\s+(?:home|house|door)\b.{0,70}\b(?:hurt|harm|kill|attack)\b|\bthreaten(?:ed|ing)?\b.{0,55}\b(?:come|coming)\b.{0,45}\b(?:home|house|door)\b.{0,65}\b(?:hurt|harm|kill|attack)\b/.test(t)
  const chineseDanger=/明确正在自伤|即将伤害自己|威胁今天上门伤害|威胁.{0,18}(?:今天|现在|马上).{0,10}(?:上门|来).{0,14}(?:伤害|打|杀)|我现在有危险|目前正面临直接危险/.test(sentence)
  return selfHarm||directDanger||imminentThreat||chineseDanger
})
const potentialSafetyCue = (s: string) => /\b(?:threat(?:ened|ening)?|danger|hurt|harm|attack|kill|suicidal|self.harm)\b|威胁|危险|伤害|自杀|自伤/i.test(s)
const demoSafetyReviewNeeded = (s: string) => !immediateSafety(s) && potentialSafetyCue(s) && !s.split(/[.!?。！？\n;]+/).every(sentence=>explicitlyNoCurrentSafety(sentence)||futureHypotheticalSafety(sentence)||historicalSafetyOnly(sentence)||!potentialSafetyCue(sentence))
const safetyAssessment = (s: string): ModelExtraction['safetyAssessment'] => immediateSafety(s) ? {status:'current_danger',evidence:[s.trim()]} : demoSafetyReviewNeeded(s) ? {status:'uncertain',evidence:[s.trim()]} : potentialSafetyCue(s) ? {status:'no_current_danger',evidence:[s.trim()]} : {status:'not_mentioned',evidence:[]}
const credentialEvidence = (s: string) => /\b(?:gave|shared|sent|revealed|provided|told them)\s+(?:them\s+)?(?:my\s+)?(?:password|passcode|otp|verification code|security code|card details|bank details|login details)\b|\b(?:password|otp|verification code|security code|card details|bank details)\s+(?:was|were)\s+(?:shared|provided|sent|disclosed)\b/i.test(s) || /把.{0,16}(?:密码|验证码|银行卡资料).{0,10}(?:告诉|发给|提供)/.test(s)
const digitalDifficultyEvidence = (s: string) => /\b(?:cannot|can't|unable to|struggle to|have difficulty (?:using|accessing|operating))\b.{0,55}\b(?:use|access|open|navigate|operate|log in|banking app|bank app|online account|digital service)\b|\b(?:banking app|bank app|online account)\b.{0,35}\b(?:does not work|won't open|cannot use|can't use|inaccessible)\b/i.test(s) || /无法使用.{0,12}(?:银行|应用|手机|账户)|不懂得操作.{0,12}(?:手机|应用|网站)/.test(s)
const distressEvidence = (s: string) => /\b(?:panic attack|cannot communicate|can't communicate|crying continuously|serious emotional distress|unable to function|desperate and unable to cope)\b/i.test(s) || /持续哭泣|无法正常沟通|严重恐慌|无法应对/.test(s)
const languageEvidence = (s: string) => /\b(?:need an interpreter|cannot understand English|can't understand English|language barrier|need language support)\b/i.test(s) || /需要翻译|语言障碍|听不懂.{0,8}(?:英语|英文)/.test(s)
const identityEvidence = (s: string) => /\b(driver'?s licence|driver'?s license|passport|identity document|identity documents|national id)\b/i.test(s) || /护照|驾照|身份证件/.test(s)
const suspiciousContactEvidence = (s: string) => /\b(?:suspicious|scam|phishing|fraudulent|impersonat\w*)\s+(?:sms|text|phone|telephone|email|website|web site|social|message|link|advertisement)|(?:sms|text|phone|telephone|email|website|web site|social|message|link|advertisement)\s+(?:is|was|seems|looks)\s+(?:a )?(?:suspicious|scam|phishing|fraudulent)\b/i.test(s) || /可疑.{0,10}(短信|电话|邮件|网站|链接|社交平台)/.test(s)
const contactChannel = (s: string) => /\b(phone call|telephone call|called|by phone|phone message)\b|电话|来电/i.test(s) ? 'Phone call' : /\b(sms|text message|texted)\b|短信/i.test(s) ? 'SMS / text message' : /\b(email|emailed)\b|邮件/i.test(s) ? 'Email' : /\b(website|web site|online store|webpage)\b|网页|网站/i.test(s) ? 'Website' : /\b(social platform|social media|social network)\b|社交平台/i.test(s) ? 'Social platform' : ''
const normalizeAmount = (v: number) => new Intl.NumberFormat('en-AU',{maximumFractionDigits:2}).format(v)
const categoryFor = (route: Route, identity: boolean): OrganizationCategory | null => route === 'bank_transfer' || route === 'card' || route === 'wallet' ? 'Banks and Payment Providers' : route === 'platform_balance' ? 'Digital Platforms' : identity ? 'Identity Recovery Services' : null
const teamFor = (route: Route, identity: boolean) => route === 'bank_transfer' ? 'Fraud / Scam Response' : route === 'card' ? 'Card Fraud / Disputes' : route === 'wallet' ? 'Payment Provider Fraud' : route === 'platform_balance' ? 'Platform Balance Support' : identity ? 'Identity Recovery Support' : null
const rec = (id: string, kind: Recommendation['kind'], organisation: OrganizationCategory | null, team: string | null, action: string, reason: string, condition?: string, routingStatus: Recommendation['routingStatus'] = 'proposed'): Recommendation => ({ id, kind, organisation, team, action, reason, condition, routingStatus, origin: 'rule_derived' })

function demoExtraction(original: string): ModelExtraction {
  const t = original; const amounts = money(t); const route = routeEvidence(t); const facts: ModelExtraction['facts'] = []
  if (route.length === 1) facts.push({key:'payment_route',value:route[0],evidence:(t.match(/.{0,28}(?:bank transfer|wire transfer|credit card|debit card|card payment|wallet|platform balance).{0,28}/i)?.[0] ?? '').trim(),certainty:'reported'})
  if (amounts.length) facts.push({key:'amount',value:String(amounts[0].value),evidence:amounts[0].raw,certainty:amounts.length>1?'unclear':'reported'})
  if (contactChannel(t)) facts.push({key:'contact_channel',value:contactChannel(t),evidence:(t.match(/.{0,20}(?:phone call|telephone call|called|sms|text message|email|website|social platform).{0,20}/i)?.[0] ?? '').trim(),certainty:'reported'})
  if (hasAction(t) && !deniedPayment(t)) facts.push({key:'transaction_status',value:'reported_completed',evidence:(t.match(/\b(transferred|sent|paid|payment went through|charged|debited|deducted)\b/i)?.[0] ?? '').trim(),certainty:'reported'})
  if (credentialEvidence(t)) facts.push({key:'credential_disclosure',value:'reported',evidence:(t.match(/.{0,30}(?:password|otp|verification code|security code|card details|bank details).{0,25}/i)?.[0] ?? '').trim(),certainty:'reported'})
  const types: ModelExtraction['caseTypes'] = []
  if (suspiciousContactEvidence(t)) types.push({value:'Suspicious scam contact',evidence:(t.match(/.{0,30}(?:suspicious|scam|phishing).{0,55}/i)?.[0] ?? '').trim()})
  if (route.length || hasAction(t) || /\b(?:lost|loss|stolen)\b.{0,25}\b(?:money|\$|AUD)\b/i.test(t)) types.push({value:'Suspected Financial Loss',evidence:(t.match(/.{0,32}(?:transferred|sent|paid|payment|lost|loss|debited|charged).{0,45}/i)?.[0] ?? '').trim()})
  if (identityEvidence(t) || credentialEvidence(t)) types.push({value:'Possible identity or account credential disclosure',evidence:(t.match(/.{0,25}(?:passport|driver'?s licence|driver'?s license|identity document|password|otp|verification code).{0,35}/i)?.[0] ?? '').trim()})
  return {summary:clean(t),safetyAssessment:safetyAssessment(t),caseTypes:types,facts,missingInformation:[],conflicts:[],vulnerabilityIndicators:[],riskSignals:[]}
}

const baseExtraction = (input: ModelExtraction | null, original: string, clarification: string, correction: string) => {
  const all = [original,clarification,correction].filter(Boolean).join('\n'); const sourceFor = (evidence: string) => grounded(original,evidence) ? 'case_intake' as const : grounded(clarification,evidence) ? 'employee_correction' as const : grounded(correction,evidence) ? 'employee_correction' as const : null
  const facts = (input?.facts ?? []).filter(f => sourceFor(f.evidence) && (f.key !== 'payment_route' || routeEvidence(f.evidence).length === 1) && (f.key !== 'credential_disclosure' || credentialEvidence(f.evidence)))
  return {all, facts, originFor:sourceFor}
}

export function analyzeCase(originalNarrative: string, caseId = id(), workerClarifications = '', employeeCorrections = '', extraction: ModelExtraction | null = null, mode: Analysis['mode'] = 'demo'): Analysis {
  const original = clean(originalNarrative); const correction = clean(employeeCorrections); const clarification = clean(workerClarifications)
  const fallback = mode === 'demo' ? demoExtraction(original) : null; const model = extraction ?? fallback
  const {all,facts,originFor} = baseExtraction(model,original,clarification,correction)
  const originalRoute = routeEvidence(original); const correctionRoutes = routeEvidence(correction); const clarificationRoutes = routeEvidence(clarification)
  const ambiguousCorrection = correctionRoutes.length > 1 || /\b(maybe|might|possibly|not sure|uncertain|could be)\b/i.test(correction)
  const correctionOverride = correctionRoutes.length === 1 && !ambiguousCorrection
  const employeeRoute = correctionOverride ? correctionRoutes[0] : clarificationRoutes.length === 1 && !/\b(maybe|might|possibly|not sure|uncertain)\b/i.test(clarification) ? clarificationRoutes[0] : null
  const supportedModelRoute = facts.find(f=>f.key==='payment_route')?.value as Route | undefined
  const rawModelRoute = supportedModelRoute && ['bank_transfer','card','wallet','platform_balance'].includes(supportedModelRoute) ? supportedModelRoute : 'unknown'
  const originalSupportedRoute = originalRoute.length === 1 ? originalRoute[0] : originalRoute.length > 1 ? 'unknown' : rawModelRoute !== 'unknown' ? rawModelRoute : 'unknown'
  let route: Route = employeeRoute ?? originalSupportedRoute
  const routeConflict = (originalRoute.length > 1) || (ambiguousCorrection && correctionRoutes.length > 0) || (!correctionOverride && correctionRoutes.length === 1 && originalRoute.length === 1 && correctionRoutes[0] !== originalRoute[0]) || (clarificationRoutes.length > 1) || (!correctionOverride && clarificationRoutes.length === 1 && originalRoute.length === 1 && clarificationRoutes[0] !== originalRoute[0])
  if (routeConflict) route = 'unknown'

  const allAmounts = money(all); const uniqueAmounts = [...new Set(allAmounts.map(x=>x.value))]
  const intakeAmounts = money(original); const amount = uniqueAmounts.length === 1 ? uniqueAmounts[0] : undefined
  const amountConflict = uniqueAmounts.length > 1
  const actionReported = hasAction(original) && !deniedPayment(original)
  const denied = deniedPayment(original)
  const paymentMentioned = /\b(?:transfer|transferred|payment|paid|pay|sent money|charge|debit)\b|转账|付款|扣款/i.test(all)
  const paymentImminent = /\b(?:about to|going to|currently|right now|in the process of)\s+(?:pay|transfer|send)|\bpressur(?:ed|ing) me to (?:pay|transfer|send)|\bthreaten(?:ing)? me to pay\b/i.test(all)
  const recent = /\b(yesterday|today|just|recently|this morning|last night|within the last day)\b|刚才|昨天|今天|最近/i.test(all)
  const institutionNotContacted = /\b(?:have not|haven't|has not|hasn't|not) contacted (?:the |their )?(?:bank|payment institution|provider)\b|尚未联系银行|没有联系银行/.test(all.toLowerCase())
  const institutionContacted = !institutionNotContacted && /\b(?:contacted|called|notified) (?:the |their )?(?:bank|payment institution|provider)\b|已联系银行|已联系支付机构/i.test(all)
  const protectiveEvidence = /\b(?:card blocked|blocked the (?:card|account|payment|transaction)|account secured|funds secured|protective action taken|security measures applied|transaction disputed|account protected|payment stopped|credentials changed)\b|已采取保护措施|已冻结|账户已保护/i.test(all)
  const unauthorized = /\b(?:i did not make|i didn't make|not authorised by me|not authorized by me|unauthorised transaction|unauthorized transaction|unknown debit|unknown charge)\b|不是我(?:刷|付)|未经授权|盗刷/i.test(all)
  const credentialExposed = credentialEvidence(all) && !/\b(?:did not|didn't|never)\s+(?:share|send|give|provide|tell)\b.{0,45}\b(?:password|otp|verification code|card details|bank details)\b/i.test(all)
  const identity = identityEvidence(all)
  const financialLoss = actionReported || unauthorized || /\b(?:lost|loss|stolen)\s+(?:AUD\s*)?\$?\d|\b(?:lost|loss|stolen)\s+\d.{0,15}\b(?:dollar|money|funds)\b/i.test(all)
  const accountControlLost = /\b(?:account was taken over|someone else controls my account|cannot access my account because it was changed|locked out after someone changed|unauthorised login has control)\b/i.test(all)
  const modelSafetyEvidence = model?.safetyAssessment.evidence.filter(e=>originFor(e)) ?? []
  const semanticDanger = mode !== 'demo' && model?.safetyAssessment.status==='current_danger' && modelSafetyEvidence.some(e=>immediateSafety(e))
  const semanticSafetyUncertain = mode !== 'demo' && model?.safetyAssessment.status==='uncertain' && modelSafetyEvidence.some(e=>potentialSafetyCue(e))
  const safety = immediateSafety(all) || Boolean(semanticDanger)
  const safetyReviewRequired = !safety && (semanticSafetyUncertain || mode==='demo' && demoSafetyReviewNeeded(all))
  const safetyReviewMessage = safetyReviewRequired ? 'Immediate human safety review required: the available information mentions a possible safety concern, but its current status is unclear. Do not treat this Demo/AI result as confirmation that the person is safe.' : ''
  const digital = digitalDifficultyEvidence(all); const distress = distressEvidence(all); const language = languageEvidence(all)
  const checkedModelVulnerabilities = (model?.vulnerabilityIndicators ?? []).filter(v=>originFor(v.evidence) && (
    v.kind==='digital_access' ? digitalDifficultyEvidence(v.evidence) : v.kind==='language_barrier' ? languageEvidence(v.evidence) : v.kind==='severe_emotional_distress' ? distressEvidence(v.evidence) : v.kind==='accessibility' ? /\b(?:wheelchair|blind|vision impairment|deaf|hearing impairment|mobility difficulty|disability|accessible access)\b/i.test(v.evidence) : /\b(?:cannot afford food|no food|without housing|homeless|cannot meet essential needs|no access to medication)\b/i.test(v.evidence)
  ))
  const hasDigitalNeed = digital || checkedModelVulnerabilities.some(v=>v.kind==='digital_access')
  const hasLanguageNeed = language || checkedModelVulnerabilities.some(v=>v.kind==='language_barrier')
  const vulnerable = [
    ...(digital ? [{title:'Digital access difficulty',evidence:(all.match(/.{0,35}(?:cannot|can't|unable to|difficulty).{0,55}(?:app|account|digital|use|access).{0,30}/i)?.[0] ?? 'A specific digital access difficulty is reported.'),suggestion:'Ask whether Community Access & Practical Support would help with the stated digital access barrier; confirm consent and service capability.',origin:correctionOverride?'employee_correction' as const:mode==='gemini'?'gemini_extracted' as const:mode==='openai'?'openai_extracted' as const:'demo_extracted' as const}] : []),
    ...(language ? [{title:'Language access support',evidence:'A language or interpreter need is reported.',suggestion:'Ask whether Community Access & Practical Support can provide suitable language assistance; confirm consent and service capability.',origin:'rule_derived' as const}] : []),
    ...(distress ? [{title:'Severe emotional distress',evidence:'A specific sign of serious distress is reported.',suggestion:'Ask whether Victim Support & Follow-up is wanted; do not diagnose or assume acceptance.',origin:'rule_derived' as const}] : []),
    ...checkedModelVulnerabilities.map(v=>({title:v.kind.replace(/_/g,' ').replace(/^./,x=>x.toUpperCase()),evidence:v.evidence,suggestion:v.kind==='digital_access'?'Ask whether Community Access & Practical Support would help with the stated digital access barrier; confirm consent and service capability.':'Review this reported support need with the person and offer appropriate options; confirm consent and service capability.',origin:originFor(v.evidence) ?? (mode==='gemini'?'gemini_extracted':'openai_extracted') as FactOrigin})),
  ] satisfies Vulnerability[]
  const modelCaseTypes = (model?.caseTypes ?? []).filter(c=>originFor(c.evidence) && (c.value==='Suspicious scam contact' ? suspiciousContactEvidence(c.evidence) : c.value==='Suspected Financial Loss' ? (hasAction(c.evidence)&&!deniedPayment(c.evidence)) || /\b(?:unauthori[sz]ed|unknown debit|unknown charge)\b/i.test(c.evidence) : identityEvidence(c.evidence)||credentialEvidence(c.evidence)))
  const caseTypes: CaseType[] = [...new Set([
    ...(modelCaseTypes.map(c=>c.value)),
    ...(suspiciousContactEvidence(original) ? ['Suspicious scam contact' as const] : []),
    ...(financialLoss ? ['Suspected Financial Loss' as const] : []),
    ...(credentialExposed || identity ? ['Possible identity or account credential disclosure' as const] : []),
  ])]

  const transactionStatus = actionReported ? 'Reported as completed' : denied ? 'No transaction reported' : paymentMentioned ? 'Not clear from the report' : 'No transaction reported'
  const routeFact = route === 'unknown' && paymentMentioned ? 'Not specified' : route === 'bank_transfer' ? 'Bank transfer' : route === 'card' ? 'Card payment' : route === 'wallet' ? 'Payment wallet' : route === 'platform_balance' ? 'Platform balance' : ''
  const amountFact = amount !== undefined ? `AUD ${normalizeAmount(amount)}` : amountConflict ? 'Conflicting reported amounts' : ''
  const channel = contactChannel(all)
  const factOrigin: FactOrigin = mode === 'demo' ? 'demo_extracted' : mode==='gemini'?'gemini_extracted':'openai_extracted'
  const reportedFacts: Fact[] = [
    {label:'Main Case Type',value:caseTypes.join(' · ') || 'Unable to determine from the information provided.',origin:modelCaseTypes.length?factOrigin:'rule_derived'},
    {label:'Transaction Status',value:transactionStatus,origin:actionReported?'case_intake':'rule_derived',evidence:actionReported?(original.match(/\b(transferred|sent|paid|payment went through|charged|debited)\b/i)?.[0] ?? ''):undefined},
    ...(channel ? [{label:'Contact Channel',value:channel,origin:factOrigin,evidence:channel}] : []),
    ...(amountFact ? [{label:'Reported Amount',value:amountFact,origin:amountConflict?'rule_derived' as const:'case_intake' as const,evidence:allAmounts.map(x=>x.raw).join('; ')}] : []),
    ...(routeFact ? [{label:'Payment Route',value:routeFact,origin:employeeRoute?'employee_correction' as const:route==='unknown'?'rule_derived' as const:factOrigin,evidence:employeeRoute?correction:originalRoute.length?original:undefined}] : []),
    ...(credentialExposed ? [{label:'Credential Disclosure',value:'Possible disclosure reported',origin:'case_intake' as const,evidence:(all.match(/.{0,30}(?:password|otp|verification code|card details|bank details).{0,25}/i)?.[0] ?? '')}] : []),
  ]

  const missingInfo: string[] = []
  const questions: string[] = []
  if (safetyReviewRequired) { missingInfo.push('Whether the person is currently in immediate danger is unclear.'); questions.push('Is the person in immediate danger right now, and can an authorised employee safely confirm their current situation?') }
  if (paymentMentioned && route === 'unknown') { missingInfo.push('The payment route is not specified.'); questions.push('How was the payment made — bank transfer, card, payment wallet, or platform balance?') }
  if (actionReported && !institutionContacted && !institutionNotContacted) { missingInfo.push('It is not stated whether the relevant institution has been contacted.'); questions.push('Have you contacted the institution that handled the payment?') }
  if (actionReported && !protectiveEvidence) { missingInfo.push('No protective action is reported.'); questions.push('Has any protective action been taken by the payment institution?') }
  if (paymentImminent) { missingInfo.push('The intended payment route or whether payment has started is unclear.'); questions.push('Has any money already been sent, and what payment method was about to be used?') }
  if (credentialExposed && !protectiveEvidence) { missingInfo.push('The affected account or credential protection status is unknown.'); questions.push('Which type of account was affected, and has its provider secured access? Do not share the secret.') }
  if (unauthorized && !/\b(?:reported to|contacted|blocked)\b.{0,30}\b(?:bank|card|provider)\b/i.test(all)) { missingInfo.push('It is not stated whether the card provider has been contacted or the card secured.'); questions.push('Have you contacted the card provider or secured the card?') }
  if (amountConflict) { missingInfo.push('Two or more different amounts are reported.'); questions.push('Which amount is supported by the information currently available?') }
  const modelMissing = (model?.missingInformation ?? []).filter(m=>questionSafe(m.question) && (m.key==='other' || !missingInfo.some(x=>x.toLowerCase().includes(m.key.replace(/_/g,' ')))))
  for (const m of modelMissing) { if (questions.length >= 3) break; missingInfo.push(m.reason); questions.push(m.question) }
  const conflicts: string[] = []
  if (amountConflict) conflicts.push(`Amount conflict: ${[...new Set(allAmounts.map(x=>`AUD ${normalizeAmount(x.value)}`))].join(' versus ')}.`)
  if (routeConflict) conflicts.push('Payment-route statements conflict or the employee correction is uncertain; confirm the route before selecting a receiving team.')
  for (const c of (model?.conflicts ?? [])) if (c.evidence.length >= 2 && c.evidence.every(e=>grounded(all,e)) && !conflicts.some(x=>x.toLowerCase().includes(c.topic.replace(/_/g,' ')))) conflicts.push(`${c.topic}: ${c.explanation}`)
  const pendingVerification = [
    ...(safetyReviewRequired ? ['Current personal safety status — pending immediate human review.'] : []),
    ...(paymentMentioned && route==='unknown' ? ['Payment route — pending verification.'] : []),
    ...(actionReported && !protectiveEvidence ? ['Protective status — pending verification.'] : []),
    ...(amountConflict || routeConflict || conflicts.length ? ['Conflicting statements — pending employee review.'] : []),
    ...(credentialExposed && !protectiveEvidence ? ['Credential protection — pending verification.'] : []),
  ]
  const clarifyingQuestions = [...new Set(questions)].filter(questionSafe).slice(0,3)
  const recentPaymentUnprotected = actionReported && recent && !protectiveEvidence
  const p1 = safety || recentPaymentUnprotected || (unauthorized && !protectiveEvidence) || (credentialExposed && !protectiveEvidence) || accountControlLost || paymentImminent
  const p2 = financialLoss || identity || credentialExposed || unauthorized
  const priority: Analysis['priority'] = p1 ? 'P1 — Immediate' : safetyReviewRequired && !p2 ? 'Priority pending confirmation' : p2 ? 'P2 — Priority' : 'P3 — Standard'
  const priorityEvidence = [
    ...(safety ? ['An explicit immediate personal safety threat is reported.'] : []),
    ...(recentPaymentUnprotected ? ['A recent completed payment is reported and protective action is not reported.'] : []),
    ...(unauthorized ? ['An unauthorised payment is explicitly reported.'] : []),
    ...(credentialExposed && !protectiveEvidence ? ['A credential disclosure is explicitly reported and protection is unknown.'] : []),
    ...(paymentImminent ? ['A suspected payment is imminent or in progress.'] : []),
  ]
  const priorityRule = safety ? 'R2: current/imminent personal safety danger overrides ordinary scam categorisation.' : safetyReviewRequired ? 'R2: safety status cannot be reliably determined; require immediate human safety review rather than defaulting to P3.' : p1 ? 'R2: immediate risk is reported; act while clarification continues.' : p2 ? 'R2: a reported financial, identity, credential, or future-payment risk needs priority review.' : 'R2: no immediate or priority risk indicator is established by the current report.'

  const recommendations: Recommendation[] = []
  if (safety) recommendations.push(rec('safety','Primary Recommendation',"Reporting Organisation's Designated Emergency Safety Contact",'Designated Safety Contact','Immediately escalate the reported personal safety threat through the organisation’s designated safety procedure.','The person reports a credible current or imminent personal safety danger.'))
  else if (safetyReviewRequired) recommendations.push(rec('safety-review','Primary Recommendation',"Reporting Organisation's Designated Emergency Safety Contact",'Designated Safety Contact','An authorised employee should promptly confirm whether the person is currently in immediate danger and follow the organisation’s safety procedure if confirmed.','The available safety information is ambiguous and must not be treated as proof that the person is safe.',undefined,'pending_clarification'))
  if (route !== 'none' && route !== 'unknown' && (financialLoss || paymentMentioned || unauthorized)) {
    const org = categoryFor(route,false)!; const team = teamFor(route,false)!
    const action = route==='bank_transfer' ? 'Ask the bank team to review the reported transfer and assess available protective options.' : route==='card' ? unauthorized ? 'Ask the card team to review the reported unauthorised charge and available card protection.' : 'Ask the card team to review the reported merchant payment and any relevant dispute pathway; do not describe it as unauthorised.' : route==='wallet' ? 'Ask the payment provider controlling the wallet to review the reported payment and available protections.' : 'Ask the platform controlling the balance to review the reported reduction and account protection.'
    recommendations.push(rec(safety?'parallel-financial':'primary',safety?'Necessary Parallel Action':'Primary Recommendation',org,team,action,'The payment route is explicitly supported by the reported facts.'))
  } else if (financialLoss || paymentMentioned || paymentImminent) {
    recommendations.push(rec(safety?'parallel-financial':'primary',safety?'Necessary Parallel Action':'Primary Recommendation',null,null,'An authorised employee should identify the institution responsible for the reported or intended payment and ask it to assess the available protective steps. Select a receiving department only after the payment route is clarified.','The report supports payment-related action but does not establish a unique receiving organisation or team.','Bank transfer → Banks and Payment Providers / Fraud / Scam Response · Card payment → Banks and Payment Providers / Card Fraud / Disputes · Payment wallet → Banks and Payment Providers / Payment Provider Fraud · Platform balance → Digital Platforms / Platform Balance Support','pending_clarification'))
  } else if (credentialExposed || identity) {
    const org = categoryFor('none',identity); const team = teamFor('none',identity)
    recommendations.push(rec(safety?'parallel-account':'primary',safety?'Necessary Parallel Action':'Primary Recommendation',org,team,'Ask the responsible account or identity service to assess protection and recovery options. Do not transmit secrets through this assistant.','The report explicitly describes identity information or a credential being disclosed.',identity?undefined:'Clarify which service or account was affected before selecting a receiving department.',identity?'proposed':'pending_clarification'))
  } else if (suspiciousContactEvidence(original)) {
    const channelValue = contactChannel(original)
    const org: OrganizationCategory = channelValue==='Website' || channelValue==='Social platform' ? 'Digital Platforms' : channelValue==='Phone call' || channelValue==='SMS / text message' ? 'Telecommunications Providers' : 'Government Scam Reporting Services'
    const team = org==='Telecommunications Providers' ? channelValue==='Phone call' ? 'Fraud & SIM Security' : 'Scam Messaging Reporting' : org==='Digital Platforms' ? 'Trust & Safety' : 'Scam Reporting & Case Coordination'
    recommendations.push(rec(safety?'follow-up-contact':'primary',safety?'Follow-up / Reporting Suggestion':'Primary Recommendation',org,team,org==='Telecommunications Providers'?'Ask the employee to record and report the suspicious contact through the relevant channel process.':'Ask the employee to preserve the report and use the appropriate reporting or platform review process.','A suspicious scam contact is reported with no higher priority payment, account, or identity route established.'))
  }
  if (hasDigitalNeed || hasLanguageNeed) recommendations.push(rec('community','Additional Recommendation','Community Support Organisations','Community Access & Practical Support','Ask whether practical, language, accessibility, or digital-operation support would help with the stated difficulty; confirm consent and service capability.','A specific access barrier is reported.'))
  if (distress) recommendations.push(rec('victim','Additional Recommendation','Victim Support Organisations','Victim Support & Follow-up','Ask whether emotional support and follow-up assistance is wanted.','A specific sign of severe emotional distress is reported.'))

  const rawSummary = model?.summary?.trim() ?? ''
  const summaryGrounded = mode !== 'demo' && rawSummary.length > 0 && rawSummary.length <= 900 && !/unsolicited|unverified by the bank|bank confirmed|confirmed by (?:the )?(?:bank|provider)|police|reported to the bank/i.test(rawSummary) && [...rawSummary.matchAll(/\b(?:AUD\s*|A\$\s*|\$\s*)(\d[\d,]*(?:\.\d+)?)/gi)].every(m=>original.toLowerCase().includes(m[0].toLowerCase())) && (!/\bbank transfer\b/i.test(rawSummary)||routeEvidence(original).includes('bank_transfer')) && (!/\b(?:card payment|credit card|debit card)\b/i.test(rawSummary)||routeEvidence(original).includes('card')) && (!/\b(?:payment wallet|third.party wallet|wallet payment)\b/i.test(rawSummary)||routeEvidence(original).includes('wallet')) && (!/\bplatform balance\b/i.test(rawSummary)||routeEvidence(original).includes('platform_balance'))
  const summary = summaryGrounded ? rawSummary : clean(original) || 'No case narrative provided.'
  const summaryOrigin: Analysis['summaryOrigin'] = summaryGrounded ? factOrigin : mode==='demo' ? 'demo_extracted' : 'case_intake'
  const reviewDecisions = Object.fromEntries(recommendations.map(r=>[r.id,{state:'pending' as const,editedAction:'',editedTeam:'',notes:''}]))
  const interimAction = safetyReviewRequired ? 'Promptly review immediate personal safety with an authorised employee; do not assume the person is safe while this uncertainty remains.' : safety ? 'Immediately escalate the reported personal safety threat through the organisation’s designated safety procedure.' : priority==='P1 — Immediate' ? p1 && !routeEvidence(all).length && financialLoss ? 'Act promptly: an authorised employee should identify and contact the institution responsible for the reported payment while clarifying the route. Do not wait for every missing detail.' : 'Ask the responsible team to assess the immediate risk and available protective steps while remaining facts are clarified.' : priority==='P2 — Priority' ? 'Arrange prompt employee review with the appropriate organisation; update urgency if the reported risk is ongoing.' : priority==='Priority pending confirmation' ? 'Priority cannot be determined from the current information; obtain prompt human review before assigning P1–P3.' : 'Record the suspicious contact and provide the relevant prevention guidance; reassess if new risk information is reported.'
  const modelExtraction = mode==='demo' ? null : model
  return {caseId,mode,originalNarrative:original,workerClarifications:clarification,employeeCorrections:correction,summary,summaryOrigin,caseTypes,reportedFacts,priority,priorityRule,priorityEvidence,interimAction,safetyReviewRequired,safetyReviewMessage,vulnerabilityIndicators:vulnerable,missingInfo:[...new Set(missingInfo)],conflicts,pendingVerification,clarifyingQuestions,modelExtraction,recommendations,reviewDecisions}
}

export function localAnalyze(narrative: string, caseId = id(), workerClarifications = '', employeeCorrections = ''): Analysis {
  return analyzeCase(narrative,caseId,workerClarifications,employeeCorrections,null,'demo')
}

export function reconcileAnalysis(raw: unknown, narrative: string, caseId: string, workerClarifications = '', employeeCorrections = '', provider: 'gemini' | 'openai' = 'gemini'): Analysis {
  const valid = validateModelExtraction(raw) ? raw : null
  return analyzeCase(narrative,caseId,workerClarifications,employeeCorrections,valid,valid?provider:'demo')
}

export function caseInformationFacts(facts: Fact[]): Fact[] {
  return facts.filter(f=>['Main Case Type','Transaction Status','Contact Channel','Reported Amount','Payment Route','Credential Disclosure'].includes(f.label))
}
