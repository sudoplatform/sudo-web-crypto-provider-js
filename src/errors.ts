/**
 * Key not found from store when using cryptoProvider
 */
export class KeyNotFoundError extends Error {
  constructor(message?: string) {
    super(message ?? 'Key not found.')
    this.name = 'KeyNotFoundError'
  }
}

export class NotImplementedError extends Error {
  constructor(message?: string) {
    super(message ?? 'Method not implemented.')
    this.name = 'NotImplementedError'
  }
}
