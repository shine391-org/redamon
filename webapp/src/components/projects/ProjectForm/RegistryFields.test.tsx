/**
 * RegistryFields numeric inputs: emptying the box keeps a draft while the
 * person types and applies the registry default on blur, never 0 (plan §22.3,
 * "clear the field: the default is used").
 *
 * Run: npx vitest run src/components/projects/ProjectForm/RegistryFields.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { RegistryFields } from './RegistryFields'
import { field } from '@/lib/reconSettings/registry'

afterEach(() => cleanup())

function renderField(name: string, value: number) {
  const updateField = vi.fn()
  render(<RegistryFields keys={[name]} data={{ [name]: value } as never} updateField={updateField as never} />)
  return { input: document.getElementById(`registry-field-${name}`) as HTMLInputElement, updateField }
}

describe('RegistryFields number input', () => {
  test.each(['routeExposureMaxRoutesPerHost', 'routeExposureMaxRps', 'ipAttributionTlsMaxProbes'])(
    'emptying %s writes nothing until blur, then the default', (name) => {
      const { input, updateField } = renderField(name, 42)
      fireEvent.change(input, { target: { value: '' } })
      expect(updateField).not.toHaveBeenCalled()
      expect(input.value).toBe('')
      fireEvent.blur(input)
      expect(updateField).toHaveBeenCalledTimes(1)
      expect(updateField).toHaveBeenCalledWith(name, field(name)!.default)
      expect(field(name)!.default).not.toBe(0)
    })

  test('a number typed after emptying is written as typed', () => {
    const { input, updateField } = renderField('routeExposureMaxRoutesPerHost', 300)
    fireEvent.change(input, { target: { value: '' } })
    fireEvent.change(input, { target: { value: '25' } })
    expect(updateField).toHaveBeenLastCalledWith('routeExposureMaxRoutesPerHost', 25)
    fireEvent.blur(input)
    expect(updateField).toHaveBeenCalledTimes(1)
  })

  test('a float field keeps its decimals', () => {
    const { input, updateField } = renderField('routeExposureMaxRps', 5)
    fireEvent.change(input, { target: { value: '2.5' } })
    expect(updateField).toHaveBeenCalledWith('routeExposureMaxRps', 2.5)
  })

  test('the bounds reach the input', () => {
    const { input } = renderField('routeExposureWorkers', 4)
    expect([input.min, input.max]).toEqual(['1', '16'])
  })
})
