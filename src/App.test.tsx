// @vitest-environment jsdom
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

let root: Root | undefined
let host: HTMLDivElement | undefined

const button = (name: string) => {
  const found=[...document.querySelectorAll('button')].find(b=>b.textContent?.toLocaleLowerCase().includes(name.toLocaleLowerCase()))
  if(!found) throw new Error(`Button not found: ${name}`)
  return found as HTMLButtonElement
}
const click = async (name: string) => act(async()=>{button(name).dispatchEvent(new MouseEvent('click',{bubbles:true}))})

afterEach(async()=>{
  if(root) await act(async()=>root?.unmount())
  root=undefined; host?.remove(); host=undefined
  vi.unstubAllGlobals()
})

describe('recommendation review workflow',()=>{
  it('keeps a reviewed safety recommendation visible through decisions, navigation, and report generation',async()=>{
    Object.assign(globalThis,{IS_REACT_ACT_ENVIRONMENT:true})
    vi.stubGlobal('fetch',vi.fn(async(input:RequestInfo|URL)=>String(input).includes('/api/status')
      ? {ok:true,json:async()=>({mode:'demo'})}
      : {ok:false,json:async()=>({mode:'demo'})}))
    host=document.createElement('div'); document.body.append(host); root=createRoot(host)
    await act(async()=>root!.render(<App/>))
    await click('Immediate safety concern')
    await click('Analyse Case')
    expect(document.body.textContent).toContain('P1 — Immediate')
    await click('Continue with current information')
    expect(document.querySelector('[data-recommendation-id="safety"]')).not.toBeNull()
    await click('Accept')
    let card=document.querySelector('[data-recommendation-id="safety"]')!
    expect(card.textContent).toContain('Accepted · not sent')
    expect(card.textContent).toContain('Immediately escalate the reported personal safety threat')
    await click('Change Decision')
    await click('Modify')
    const action=document.querySelector<HTMLTextAreaElement>('textarea[aria-label="Modified proposed action"]')!
    await act(async()=>{
      const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')!.set!
      setter.call(action,'Escalate under the employee safety procedure now.')
      action.dispatchEvent(new Event('input',{bubbles:true}))
    })
    await click('Reject')
    card=document.querySelector('[data-recommendation-id="safety"]')!
    expect(card.textContent).toContain('Rejected · retained')
    expect(card.textContent).toContain('Why suggested')
    expect(card.textContent).toContain('Employee-modified proposal')
    await click('Review analysis')
    await click('Continue with current information')
    expect(document.querySelector('[data-recommendation-id="safety"]')?.textContent).toContain('Rejected · retained')
    await click('Generate Case Report')
    expect(document.body.textContent).toContain('Employee decision: rejected')
    expect(document.body.textContent).toContain('Original recommendation: Immediately escalate the reported personal safety threat')
    expect(document.body.textContent).toContain('Employee-modified action: Escalate under the employee safety procedure now.')
    expect(document.body.textContent).toContain('Original justification: The person reports a credible current or imminent personal safety danger.')
  })
})
