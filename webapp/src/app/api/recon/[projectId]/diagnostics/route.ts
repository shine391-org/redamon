import { NextRequest } from 'next/server'
import { readReconDiagnostics } from '@/lib/reconContinuation'
import { internalError } from '@/lib/routeErrors'

export async function GET(request: NextRequest, { params }: { params: Promise<{ projectId: string }> }) {
  try {
    return await readReconDiagnostics((await params).projectId, request.nextUrl.searchParams.get('run_id'))
  } catch (err) {
    return internalError(err, 'Failed to read recon diagnostics')
  }
}
