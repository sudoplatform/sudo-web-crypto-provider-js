import { KeyNotFoundError } from './errors'
import { WebSudoCryptoProvider } from './webSudoCryptoProvider'

global.crypto = require('isomorphic-webcrypto')
global.btoa = (b) => Buffer.from(b).toString('base64')
global.atob = (a) => Buffer.from(a, 'base64').toString()

const cryptoProvider = new WebSudoCryptoProvider('namespace', 'servicename')

afterEach(() => {
  return cryptoProvider.removeAllKeys()
})

describe('sudoCryptoProvider', () => {
  const symmetricKey = '14A9B3C3540142A11E70ACBB1BD8969F'

  describe('addPassword', () => {
    it('should add then delete a password', async () => {
      await cryptoProvider.addPassword(
        new TextEncoder().encode('am@z1ing'),
        'testKey.password',
      )
      const passwordBuffer = await cryptoProvider.getPassword(
        'testKey.password',
      )

      expect(passwordBuffer).toBeDefined()
      const password = new TextDecoder().decode(passwordBuffer)
      expect(password).toBe('am@z1ing')

      await cryptoProvider.deletePassword('testKey.password')
      const passwordTest = await cryptoProvider.getPassword('testKey.password')
      expect(passwordTest).toBeUndefined()
    })
  })

  describe('updatePassword', () => {
    it('should update a password', async () => {
      await cryptoProvider.addPassword(
        new TextEncoder().encode('am@z1ing'),
        'testKey.password',
      )

      await cryptoProvider.updatePassword(
        new TextEncoder().encode('w0W!'),
        'testKey.password',
      )

      const passwordBuffer = await cryptoProvider.getPassword(
        'testKey.password',
      )

      expect(passwordBuffer).toBeDefined()
      expect(new TextDecoder().decode(passwordBuffer)).toBe('w0W!')
    })

    it('should throw keyNotFoundError when updating a password that does not exist', async () => {
      await expect(
        cryptoProvider.updatePassword(
          new TextEncoder().encode('w0W!'),
          'testKey.password',
        ),
      ).rejects.toThrow(KeyNotFoundError)
    })
  })

  describe('removeAllKeys', () => {
    it('should remove all keys', async () => {
      const symmetricKeyBuffer = new TextEncoder().encode(symmetricKey)

      await cryptoProvider.addSymmetricKey(
        symmetricKeyBuffer,
        'testKey.symmetric',
      )
      await cryptoProvider.addPassword(
        new TextEncoder().encode('am@z1ing'),
        'testKey.password',
      )
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const symmetricKeyAnswer = await cryptoProvider.getSymmetricKey(
        'testKey.symmetric',
      )
      expect(new TextDecoder().decode(symmetricKeyAnswer)).toBe(symmetricKey)

      const passwordAnswer = await cryptoProvider.getPassword(
        'testKey.password',
      )
      expect(new TextDecoder().decode(passwordAnswer)).toBe('am@z1ing')

      const publicKeyAnswer = await cryptoProvider.getPublicKey(
        'testKey.keyPair',
      )
      expect(publicKeyAnswer).toBeDefined()
      const privateKeyAnswer = await cryptoProvider.getPrivateKey(
        'testKey.keyPair',
      )
      expect(privateKeyAnswer).toBeDefined()

      await cryptoProvider.removeAllKeys()

      const symmetricRemoval = await cryptoProvider.getSymmetricKey(
        'testKey.symmetric',
      )
      expect(symmetricRemoval).toBeUndefined()
      const passwordRemoval = await cryptoProvider.getPassword(
        'testKey.password',
      )
      expect(passwordRemoval).toBeUndefined()
      const publicKeyRemoval = await cryptoProvider.getPublicKey(
        'testKey.keyPair',
      )
      expect(publicKeyRemoval).toBeUndefined()
      const privateKeyRemoval = await cryptoProvider.getPrivateKey(
        'testKey.keyPair',
      )
      expect(privateKeyRemoval).toBeUndefined()
    })
  })

  describe('addSymmetricKey', () => {
    it('should add then delete symmetric key', async () => {
      const symmetricKeyBuffer = new TextEncoder().encode(symmetricKey)

      await cryptoProvider.addSymmetricKey(
        symmetricKeyBuffer,
        'testKey.symmetric',
      )

      const key = await cryptoProvider.getSymmetricKey('testKey.symmetric')
      expect(key).toBeDefined()
      const decodedKey = new TextDecoder().decode(key)

      expect(decodedKey).toBe(symmetricKey)

      await cryptoProvider.deleteSymmetricKey('testKey.symmetric')

      const deletedKey = await cryptoProvider.getSymmetricKey(
        'testKey.symmetric',
      )
      expect(deletedKey).toBeUndefined()
    })
  })

  describe('getSymmetricKey', () => {
    it('should get symmetric key when set', async () => {
      const symmetricKeyBuffer = new TextEncoder().encode(symmetricKey)

      await cryptoProvider.addSymmetricKey(
        symmetricKeyBuffer,
        'testKey.symmetric',
      )

      const buffer = await cryptoProvider.getSymmetricKey('testKey.symmetric')

      expect(buffer).toBeDefined()

      expect(
        Buffer.compare(
          new Uint8Array(buffer ?? new ArrayBuffer(0)),
          symmetricKeyBuffer,
        ),
      ).toEqual(0)
    })

    it('should be undefined when symmetric key not set', async () => {
      const key = await cryptoProvider.getSymmetricKey('random.symmetric')
      expect(key).toBeUndefined()
    })
  })

  describe('generateSymmetricKey', () => {
    it('should generate and store new symmetric key', async () => {
      const existingKey = await cryptoProvider.getSymmetricKey(
        'testKey.symmetric',
      )
      expect(existingKey).toBeUndefined()

      await cryptoProvider.generateSymmetricKey('testKey.symmetric')
      const newKey = await cryptoProvider.getSymmetricKey('testKey.symmetric')
      expect(newKey).toBeDefined()
      expect(newKey?.byteLength).toBe(32)
    })
  })

  describe('encryptWithSymmetricKeyName', () => {
    it('should throw KeyNotFoundError when symmetric key not set', async () => {
      await expect(
        cryptoProvider.encryptWithSymmetricKeyName(
          'random.symmetric',
          new TextEncoder().encode('data to encrypt'),
        ),
      ).rejects.toThrow(KeyNotFoundError)
    })

    it('should encrypt then decrypt', async () => {
      await cryptoProvider.generateSymmetricKey('testKey.symmetric')

      const encryptedBuffer = await cryptoProvider.encryptWithSymmetricKeyName(
        'testKey.symmetric',
        new TextEncoder().encode('data to encrypt'),
      )

      const decryptedBuffer = await cryptoProvider.decryptWithSymmetricKeyName(
        'testKey.symmetric',
        encryptedBuffer,
      )

      const decrypted = new TextDecoder().decode(decryptedBuffer)
      expect(decrypted).toBe('data to encrypt')
    })
  })

  describe('decryptWithSymmetricKeyName', () => {
    it('should encrypt then decrypt with symmetric key passed in', async () => {
      await cryptoProvider.generateSymmetricKey('testKey.symmetric')

      const encryptedBuffer = await cryptoProvider.encryptWithSymmetricKeyName(
        'testKey.symmetric',
        new TextEncoder().encode('data to encrypt'),
      )

      const key = await cryptoProvider.getSymmetricKey('testKey.symmetric')

      const decryptedBuffer = await cryptoProvider.decryptWithSymmetricKey(
        key as ArrayBuffer,
        encryptedBuffer,
      )

      const decrypted = new TextDecoder().decode(decryptedBuffer)
      expect(decrypted).toBe('data to encrypt')
    })
  })

  describe('generateKeyPair', () => {
    it('should generate and store new key pair', async () => {
      const existingPublicKey = await cryptoProvider.getPublicKey(
        'testKey.keyPair',
      )
      expect(existingPublicKey).toBeUndefined()

      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const generatedPublicKey = await cryptoProvider.getPublicKey(
        'testKey.keyPair',
      )
      expect(generatedPublicKey).toBeDefined()

      const generatedPrivateKey = await cryptoProvider.getPrivateKey(
        'testKey.keyPair',
      )
      expect(generatedPrivateKey).toBeDefined()
    })
  })

  describe('encryptWithPublicKey', () => {
    it('should throw KeyNotFoundError when public key not set', async () => {
      await expect(
        cryptoProvider.encryptWithPublicKey(
          'random.keyPair',
          new TextEncoder().encode('data to encrypt'),
        ),
      ).rejects.toThrow(KeyNotFoundError)
    })

    it('should encrypt with public key then decrypt with private key', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const encryptedBuffer = await cryptoProvider.encryptWithPublicKey(
        'testKey.keyPair',
        new TextEncoder().encode('data to encrypt'),
      )

      const decryptedBuffer = await cryptoProvider.decryptWithPrivateKey(
        'testKey.keyPair',
        encryptedBuffer,
      )

      const decrypted = new TextDecoder().decode(decryptedBuffer)

      expect(decrypted).toBe('data to encrypt')

      new Uint8Array(encryptedBuffer).fill(0)
      new Uint8Array(decryptedBuffer).fill(0)

      expect(new Uint8Array(encryptedBuffer)).toEqual(
        new Uint8Array(encryptedBuffer.byteLength),
      )
      expect(new Uint8Array(decryptedBuffer)).toEqual(
        new Uint8Array(decryptedBuffer.byteLength),
      )
    })

    it('should export RSA private key as PKCS#8 object, RSA public key as SPKI then PEM encode both.', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const privateKeyPKCS8 = await cryptoProvider.getPrivateKey(
        'testKey.keyPair',
      )
      expect(privateKeyPKCS8).toBeDefined()
      const publicKeySPKI = await cryptoProvider.getPublicKey('testKey.keyPair')
      expect(publicKeySPKI).toBeDefined()
    })
  })
})
