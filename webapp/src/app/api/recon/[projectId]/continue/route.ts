import { NextRequest, NextResponse } from 'next/server'
import { continueRecon } from '@/lib/reconContinuation'
import { internalError } from '@/lib/routeErrors'

export async function POST(request: NextRequest, { params }: { params: Promise<{ projectId: string }> }) {
  try {
    const raw = await request.text()
    if (raw.length > 1024) return NextResponse.json({ error: 'Invalid continuation request' }, { status: 400 })
    const body = JSON.parse(raw)
    return await continueRecon((await params).projectId, body)
  } catch (err) {
    if (err instanceof SyntaxError) return NextResponse.json({ error: 'Invalid continuation request' }, { status: 400 })
    return internalError(err, 'Failed to continue recon')
  }
}
