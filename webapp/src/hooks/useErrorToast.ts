'use client'

import { useEffect, useRef } from 'react'
import { useToast } from '@/components/ui'

/**
 * Toast an error each time a NEW one arrives. Keyed on the error object rather
 * than on the effect running: the toast context changes identity whenever a
 * toast is added, so a plain effect would show the same error again and again.
 */
export function useErrorToast(error: { message: string } | null | undefined, title?: string): void {
  const toast = useToast()
  const shown = useRef<unknown>(null)
  useEffect(() => {
    if (!error || error === shown.current) return
    shown.current = error
    toast.error(error.message, title)
  }, [error, title, toast])
}
