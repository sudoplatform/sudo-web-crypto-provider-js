import { webcrypto } from 'node:crypto'

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
})
// Workaround for `jsdom` test environment not providing TextEncoder and
// TextDecoder.
global.TextEncoder = require('util').TextEncoder
global.TextDecoder = require('util').TextDecoder
