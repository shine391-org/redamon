import { NextResponse } from 'next/server'
import { agentFetch } from '@/lib/agentFetch'

const INACTIVE = { ngrok: { active: false }, chisel: { active: false } }

// Read-only indicator: an unreachable agent reads as "no tunnel", never an error.
export async function GET() {
  try {
    const resp = await agentFetch('/tunnel-status', { cache: 'no-store' }, { timeoutMs: 5_000 })
    if (!resp.ok) return NextResponse.json(INACTIVE, { status: 200 })
    return NextResponse.json(await resp.json())
  } catch {
    return NextResponse.json(INACTIVE)
  }
}
