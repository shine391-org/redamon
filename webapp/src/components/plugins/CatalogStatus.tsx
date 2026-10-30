'use client'

import type { CatalogView } from '@/lib/plugins/pageModel'
import styles from './plugins.module.css'

const ERROR_LABEL: Record<Exclude<CatalogView['state'], 'ok'>, string> = {
  unreachable: 'Catalog unreachable',
  invalid: 'Catalog invalid',
  untrusted: 'Catalog not trusted',
}

/** The state of the signed plugin catalog in use, with what to do about it. */
export function CatalogStatus({ catalog }: { catalog: CatalogView }) {
  if (catalog.state !== 'ok') {
    return (
      <div className="alert alertWarning" role="status" data-testid="catalog-status">
        <div className="alertContent">
          <div className="alertTitle">{ERROR_LABEL[catalog.state]}</div>
          {catalog.message && <div className="alertMessage">{catalog.message}</div>}
          {catalog.detail && (
            <div className="alertMessage" data-testid="catalog-detail">
              {catalog.detail}
            </div>
          )}
          {catalog.details && catalog.details.length > 0 && (
            <ul className="alertMessage" data-testid="catalog-details">
              {catalog.details.map((d, i) => (
                <li key={i}>{d}</li>
              ))}
            </ul>
          )}
        </div>
      </div>
    )
  }
  return (
    <div className={styles.titleRow} data-testid="catalog-status">
      <span className={`chip ${catalog.official ? 'chipSuccess' : 'chipWarning'}`}>
        {catalog.official ? 'Official catalog' : 'Custom catalog'}
      </span>
      {catalog.extraKey && (
        <span className={styles.notice}>
          Signed with a key an administrator added (PLUGINS_EXTRA_TRUSTED_KEYS), not by the RedAmon plugin repository.
        </span>
      )}
      {catalog.replayed && (
        <span className={styles.notice}>An older copy was served; the last verified catalog is used.</span>
      )}
    </div>
  )
}
