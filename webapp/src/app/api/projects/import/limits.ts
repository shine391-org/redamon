/**
 * The project import's default upload cap, shared by the route and the import
 * dialog that states it.
 *
 * The archive and its multipart envelope must fit under Next's request-body cap
 * (`experimental.proxyClientMaxBodySize` in next.config.ts, 60 MB, the same as
 * nginx's client_max_body_size): past it the body reaches the route truncated,
 * so a higher cap here could never be reached.
 */
export const DEFAULT_IMPORT_MAX_UPLOAD_BYTES = 55 * 1024 * 1024

export const IMPORT_MAX_UPLOAD_LABEL = `${DEFAULT_IMPORT_MAX_UPLOAD_BYTES / 1024 / 1024} MB`
