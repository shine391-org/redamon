/**
 * The settings page tells a missing project from an outage: under its fixed
 * "Failed to load project settings." it shows the cause (code and status).
 *
 * Run: npx vitest run --no-file-parallelism "src/app/projects/[id]/settings/page.test.tsx"
 */
import { test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({ query: { data: undefined as unknown, isLoading: false, error: null as unknown } }))

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'p1' }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))
vi.mock('@/components/projects', () => ({ ProjectForm: () => <div>form</div> }))
vi.mock('@/hooks/useProjects', () => ({
  useProjectById: () => h.query,
  useUpdateProject: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ setCurrentProject: vi.fn() }) }))
vi.mock('./page.module.css', () => ({ default: new Proxy({}, { get: (_t, k) => String(k) }) }))

import ProjectSettingsPage from './page'

afterEach(cleanup)

test('a server failure shows its code and status', () => {
  h.query = { data: undefined, isLoading: false, error: new ApiError({ reason: 'Failed to fetch project', status: 500, code: 'P2024' }) }
  render(<ProjectSettingsPage />)
  expect(screen.getByText('Failed to load project settings.')).toBeInTheDocument()
  expect(screen.getByText('Failed to fetch project (P2024 · HTTP 500)')).toBeInTheDocument()
})

test('a missing project reads differently from an outage', () => {
  h.query = { data: undefined, isLoading: false, error: new ApiError({ reason: 'Not found', status: 404 }) }
  render(<ProjectSettingsPage />)
  expect(screen.getByText('Not found (HTTP 404)')).toBeInTheDocument()
})
