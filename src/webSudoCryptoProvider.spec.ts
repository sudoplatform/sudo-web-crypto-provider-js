import {
  Base64,
  Buffer as BufferUtil,
  DefaultSudoKeyArchive,
  DefaultSudoKeyManager,
  EncryptionAlgorithm,
  KeyArchiveIncorrectPasswordError,
  KeyArchiveKeyType,
  KeyDataKeyType,
  KeyNotFoundError,
  SignatureAlgorithm,
  UnrecognizedAlgorithmError,
} from '@sudoplatform/sudo-common'
import { v4 } from 'uuid'
import { LocalStorageStore } from './localStorageStore'
import { WebSudoCryptoProvider } from './webSudoCryptoProvider'

const cryptoProvider = new WebSudoCryptoProvider('namespace', 'servicename')

afterEach(async () => {
  await cryptoProvider.removeAllKeys()
})

describe('sudoCryptoProvider', () => {
  const symmetricKey = '14A9B3C3540142A11E70ACBB1BD8969F'

  describe('addPassword', () => {
    it('should add then delete a password', async () => {
      await cryptoProvider.addPassword(
        BufferUtil.fromString('am@z1ing'),
        'testKey.password',
      )
      const passwordBuffer =
        await cryptoProvider.getPassword('testKey.password')

      expect(passwordBuffer).toBeDefined()
      const password = BufferUtil.toString(passwordBuffer!)
      expect(password).toBe('am@z1ing')

      await cryptoProvider.deletePassword('testKey.password')
      const passwordTest = await cryptoProvider.getPassword('testKey.password')
      expect(passwordTest).toBeUndefined()
    })
  })

  describe('updatePassword', () => {
    it('should update a password', async () => {
      await cryptoProvider.addPassword(
        BufferUtil.fromString('am@z1ing'),
        'testKey.password',
      )

      await cryptoProvider.updatePassword(
        BufferUtil.fromString('w0W!'),
        'testKey.password',
      )

      const passwordBuffer =
        await cryptoProvider.getPassword('testKey.password')

      expect(passwordBuffer).toBeDefined()
      expect(BufferUtil.toString(passwordBuffer!)).toBe('w0W!')
    })

    it('should throw keyNotFoundError when updating a password that does not exist', async () => {
      await expect(
        cryptoProvider.updatePassword(
          BufferUtil.fromString('w0W!'),
          'testKey.password',
        ),
      ).rejects.toThrow(new KeyNotFoundError())
    })
  })

  describe('removeAllKeys', () => {
    it('should remove all keys', async () => {
      const symmetricKeyBuffer = BufferUtil.fromString(symmetricKey)

      await cryptoProvider.addSymmetricKey(
        symmetricKeyBuffer,
        'testKey.symmetric',
      )
      await cryptoProvider.addPassword(
        BufferUtil.fromString('am@z1ing'),
        'testKey.password',
      )
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const symmetricKeyAnswer =
        await cryptoProvider.getSymmetricKey('testKey.symmetric')
      expect(symmetricKeyAnswer).toBeDefined()
      expect(BufferUtil.toString(symmetricKeyAnswer!)).toBe(symmetricKey)

      const passwordAnswer =
        await cryptoProvider.getPassword('testKey.password')
      expect(passwordAnswer).toBeDefined()
      expect(BufferUtil.toString(passwordAnswer!)).toBe('am@z1ing')

      const publicKeyAnswer =
        await cryptoProvider.getPublicKey('testKey.keyPair')
      expect(publicKeyAnswer).toBeDefined()
      const privateKeyAnswer =
        await cryptoProvider.getPrivateKey('testKey.keyPair')
      expect(privateKeyAnswer).toBeDefined()

      await cryptoProvider.removeAllKeys()

      const symmetricRemoval =
        await cryptoProvider.getSymmetricKey('testKey.symmetric')
      expect(symmetricRemoval).toBeUndefined()
      const passwordRemoval =
        await cryptoProvider.getPassword('testKey.password')
      expect(passwordRemoval).toBeUndefined()
      const publicKeyRemoval =
        await cryptoProvider.getPublicKey('testKey.keyPair')
      expect(publicKeyRemoval).toBeUndefined()
      const privateKeyRemoval =
        await cryptoProvider.getPrivateKey('testKey.keyPair')
      expect(privateKeyRemoval).toBeUndefined()
    })
  })

  describe('addSymmetricKey', () => {
    it('should add then delete symmetric key', async () => {
      const symmetricKeyBuffer = BufferUtil.fromString(symmetricKey)

      await cryptoProvider.addSymmetricKey(
        symmetricKeyBuffer,
        'testKey.symmetric',
      )

      const key = await cryptoProvider.getSymmetricKey('testKey.symmetric')
      expect(key).toBeDefined()
      const decodedKey = BufferUtil.toString(key!)

      expect(decodedKey).toBe(symmetricKey)

      await cryptoProvider.deleteSymmetricKey('testKey.symmetric')

      const deletedKey =
        await cryptoProvider.getSymmetricKey('testKey.symmetric')
      expect(deletedKey).toBeUndefined()
    })
  })

  describe('getSymmetricKey', () => {
    it('should get symmetric key when set', async () => {
      const symmetricKeyBuffer = BufferUtil.fromString(symmetricKey)

      await cryptoProvider.addSymmetricKey(
        symmetricKeyBuffer,
        'testKey.symmetric',
      )

      const buffer = await cryptoProvider.getSymmetricKey('testKey.symmetric')

      expect(buffer).toBeDefined()
      expect(Base64.encode(buffer!)).toEqual(Base64.encode(symmetricKeyBuffer))
    })

    it('should be undefined when symmetric key not set', async () => {
      const key = await cryptoProvider.getSymmetricKey('random.symmetric')
      expect(key).toBeUndefined()
    })
  })

  describe('doesSymmetricKeyExist', () => {
    it('should return true if the key exists', async () => {
      const symmetricKeyBuffer = BufferUtil.fromString(symmetricKey)

      await cryptoProvider.addSymmetricKey(
        symmetricKeyBuffer,
        'testKey.symmetric',
      )

      const result =
        await cryptoProvider.doesSymmetricKeyExist('testKey.symmetric')
      expect(result).toBeTruthy()
    })

    it('should return false if the key does not exists', async () => {
      const result =
        await cryptoProvider.doesSymmetricKeyExist('random.symmetric')
      expect(result).toBeFalsy()
    })
  })

  describe('generateSymmetricKey', () => {
    it('should generate and store new symmetric key', async () => {
      const existingKey =
        await cryptoProvider.getSymmetricKey('testKey.symmetric')
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
          BufferUtil.fromString('data to encrypt'),
        ),
      ).rejects.toThrow(new KeyNotFoundError())
    })

    it('should encrypt then decrypt', async () => {
      await cryptoProvider.generateSymmetricKey('testKey.symmetric')

      const encryptedBuffer = await cryptoProvider.encryptWithSymmetricKeyName(
        'testKey.symmetric',
        BufferUtil.fromString('data to encrypt'),
      )

      const decryptedBuffer = await cryptoProvider.decryptWithSymmetricKeyName(
        'testKey.symmetric',
        encryptedBuffer,
      )

      const decrypted = BufferUtil.toString(decryptedBuffer)
      expect(decrypted).toBe('data to encrypt')
    })

    it('should encrypt then decrypt AES-GCM', async () => {
      await cryptoProvider.generateSymmetricKey('testKey.symmetric')

      const iv = await cryptoProvider.generateRandomData(12)
      const encryptedBuffer = await cryptoProvider.encryptWithSymmetricKeyName(
        'testKey.symmetric',
        BufferUtil.fromString('data to encrypt'),
        {
          iv,
          algorithm: EncryptionAlgorithm.AesGcmNoPadding,
        },
      )

      const decryptedBuffer = await cryptoProvider.decryptWithSymmetricKeyName(
        'testKey.symmetric',
        encryptedBuffer,
        {
          iv,
          algorithm: EncryptionAlgorithm.AesGcmNoPadding,
        },
      )

      const decrypted = BufferUtil.toString(decryptedBuffer)
      expect(decrypted).toBe('data to encrypt')
    })
  })

  describe('decryptWithSymmetricKeyName', () => {
    it('should encrypt then decrypt with symmetric key passed in', async () => {
      await cryptoProvider.generateSymmetricKey('testKey.symmetric')

      const encryptedBuffer = await cryptoProvider.encryptWithSymmetricKeyName(
        'testKey.symmetric',
        BufferUtil.fromString('data to encrypt'),
      )

      const key = await cryptoProvider.getSymmetricKey('testKey.symmetric')

      const decryptedBuffer = await cryptoProvider.decryptWithSymmetricKey(
        key as ArrayBuffer,
        encryptedBuffer,
      )

      const decrypted = BufferUtil.toString(decryptedBuffer)
      expect(decrypted).toBe('data to encrypt')
    })
  })

  describe('deletePublicKey', () => {
    it('should remove existing public key', async () => {
      await cryptoProvider.generateKeyPair('testKey.publicKey')

      let publicKey = await cryptoProvider.getPublicKey('testKey.publicKey')
      expect(publicKey).toBeTruthy()

      await cryptoProvider.deletePublicKey('testKey.publicKey')

      publicKey = await cryptoProvider.getPublicKey('testKey.publicKey')
      expect(publicKey).toBeUndefined()
    })

    it('should return silently if the key does not exist', async () => {
      await cryptoProvider.deletePublicKey('random.publicKey')
    })
  })

  describe('generateKeyPair', () => {
    it('should generate and store new key pair', async () => {
      const existingPublicKey =
        await cryptoProvider.getPublicKey('testKey.keyPair')
      expect(existingPublicKey).toBeUndefined()

      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const generatedPublicKey =
        await cryptoProvider.getPublicKey('testKey.keyPair')
      expect(generatedPublicKey).toBeDefined()

      const generatedPrivateKey =
        await cryptoProvider.getPrivateKey('testKey.keyPair')
      expect(generatedPrivateKey).toBeDefined()
    })
  })

  describe('doesPrivateKeyExist', () => {
    it('should return true if the key exists', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const result = await cryptoProvider.doesPrivateKeyExist('testKey.keyPair')
      expect(result).toBeTruthy()
    })

    it('should return false if the key does not exists', async () => {
      const result = await cryptoProvider.doesPrivateKeyExist('random.keyPair')
      expect(result).toBeFalsy()
    })
  })

  describe('encryptWithPublicKey', () => {
    it('should throw KeyNotFoundError when public key not set', async () => {
      await expect(
        cryptoProvider.encryptWithPublicKeyName(
          'random.keyPair',
          BufferUtil.fromString('data to encrypt'),
        ),
      ).rejects.toThrow(new KeyNotFoundError())
    })

    it('should encrypt with public key specified by name then decrypt with private key', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const encryptedBuffer = await cryptoProvider.encryptWithPublicKeyName(
        'testKey.keyPair',
        BufferUtil.fromString('data to encrypt'),
      )

      const decryptedBuffer = await cryptoProvider.decryptWithPrivateKey(
        'testKey.keyPair',
        encryptedBuffer,
      )

      const decrypted = BufferUtil.toString(decryptedBuffer)

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

    it('should encrypt with public key then decrypt with private key', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const publicKey = await cryptoProvider.getPublicKey('testKey.keyPair')
      if (!publicKey?.keyData) {
        fail('public key data unexpectedly not found')
      }

      const encryptedBuffer = await cryptoProvider.encryptWithPublicKey(
        publicKey?.keyData,
        BufferUtil.fromString('data to encrypt'),
      )

      const decryptedBuffer = await cryptoProvider.decryptWithPrivateKey(
        'testKey.keyPair',
        encryptedBuffer,
      )

      const decrypted = BufferUtil.toString(decryptedBuffer)

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

    it('should export RSA private key as PKCS#8 object', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const privateKeyPKCS8Binary =
        await cryptoProvider.getPrivateKey('testKey.keyPair')
      expect(privateKeyPKCS8Binary).toBeDefined()
      if (!privateKeyPKCS8Binary) {
        fail('privateKeyPKCS8Binary unexpectedly undefined')
      }

      await expect(
        crypto.subtle.importKey(
          'pkcs8',
          new Uint8Array(privateKeyPKCS8Binary),
          { name: 'RSA-OAEP', hash: 'SHA-1' },
          true,
          ['decrypt'],
        ),
      ).resolves.toBeDefined()
    })

    it('should export RSA public key in SPKI format', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const publicKeySPKIBinary =
        await cryptoProvider.getPublicKey('testKey.keyPair')
      expect(publicKeySPKIBinary).toBeDefined()
      if (!publicKeySPKIBinary) {
        fail('publicKeySPKIBinary unexpectedly undefined')
      }

      // The base64 encoding of a public key in SPKI (SubjectPublicKeyInfo) format
      // always starts with `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A` which encodes the algorithm
      // for which the key is to be used. We can test for correct format by looking
      // for that prefix in the base64 encoding of the exported public key
      const publicKeySPKI = Buffer.from(publicKeySPKIBinary.keyData).toString(
        'base64',
      )
      expect(publicKeySPKI).toMatch(/^MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A/)
    })
  })

  describe('generateSignatureWithPrivateKey', () => {
    it('should throw KeyNotFoundError when private key not set', async () => {
      await expect(
        cryptoProvider.generateSignatureWithPrivateKey(
          'random.keyPair',
          BufferUtil.fromString('data to sign'),
        ),
      ).rejects.toThrow(new KeyNotFoundError())
    })

    it('should sign with private key then verify with public key', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const signature = await cryptoProvider.generateSignatureWithPrivateKey(
        'testKey.keyPair',
        BufferUtil.fromString('data to sign'),
      )
      expect(signature).toBeTruthy()

      const verified = await cryptoProvider.verifySignatureWithPublicKey(
        'testKey.keyPair',
        BufferUtil.fromString('data to sign'),
        signature,
      )

      expect(verified).toBe(true)
    })

    it('should sign with private key then verify with public key specifying algorithm', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const signature = await cryptoProvider.generateSignatureWithPrivateKey(
        'testKey.keyPair',
        BufferUtil.fromString('data to sign'),
        {
          algorithm: SignatureAlgorithm.RsaPkcs15Sha256,
        },
      )
      expect(signature).toBeTruthy()

      const verified = await cryptoProvider.verifySignatureWithPublicKey(
        'testKey.keyPair',
        BufferUtil.fromString('data to sign'),
        signature,
        {
          algorithm: SignatureAlgorithm.RsaPkcs15Sha256,
        },
      )

      expect(verified).toBe(true)
    })

    it('should throw UnrecognizedAlgorithmError if unrecognized algorithm name used', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      await expect(
        cryptoProvider.generateSignatureWithPrivateKey(
          'testKey.keyPair',
          BufferUtil.fromString('data to sign'),
          {
            algorithm: 'no-such-algorithm' as SignatureAlgorithm,
          },
        ),
      ).rejects.toEqual(new UnrecognizedAlgorithmError())
    })
  })

  describe('verifySignatureWithPublicKey', () => {
    it('should throw KeyNotFoundError when public key not set', async () => {
      await expect(
        cryptoProvider.verifySignatureWithPublicKey(
          'random.keyPair',
          BufferUtil.fromString('data to sign'),
          BufferUtil.fromString('signature'),
        ),
      ).rejects.toThrow(new KeyNotFoundError())
    })

    it('should fail with verifying with different key or data', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')
      await cryptoProvider.generateKeyPair('testKey.keyPair2')

      const signature = await cryptoProvider.generateSignatureWithPrivateKey(
        'testKey.keyPair',
        BufferUtil.fromString('data to sign'),
      )
      let verified = await cryptoProvider.verifySignatureWithPublicKey(
        'testKey.keyPair',
        BufferUtil.fromString('data to sign'),
        BufferUtil.fromString('signature'),
      )
      expect(verified).toBe(false)

      verified = await cryptoProvider.verifySignatureWithPublicKey(
        'testKey.keyPair',
        BufferUtil.fromString('different data to sign'),
        signature,
      )
      expect(verified).toBe(false)

      verified = await cryptoProvider.verifySignatureWithPublicKey(
        'testKey.keyPair2',
        BufferUtil.fromString('data to encrypt'),
        signature,
      )
      expect(verified).toBe(false)
    })

    it('should throw UnrecognizedAlgorithmError if unrecognized algorithm name used', async () => {
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      await expect(
        cryptoProvider.verifySignatureWithPublicKey(
          'random.keyPair',
          BufferUtil.fromString('data to sign'),
          BufferUtil.fromString('signature'),
          {
            algorithm: 'no-such-algorithm' as SignatureAlgorithm,
          },
        ),
      ).rejects.toEqual(new UnrecognizedAlgorithmError())
    })
  })

  describe('exportKeys', () => {
    it('generates expected result', async () => {
      const keyPairName = 'testKey.keyPair'
      const passwordName = 'testKey.password'
      const symmetricKeyName = 'testKey.symmetric'
      await cryptoProvider.generateKeyPair(keyPairName)
      await cryptoProvider.addPassword(
        BufferUtil.fromString('am@z1ing'),
        passwordName,
      )
      await cryptoProvider.generateSymmetricKey(symmetricKeyName)

      const exported = await cryptoProvider.exportKeys()
      expect(exported).toHaveLength(4)
      const publicKey = exported.find(
        (key) => key.type === KeyDataKeyType.RSAPublicKey,
      )
      expect(publicKey).toBeDefined()
      expect(publicKey?.name).toEqual(keyPairName)
      const privateKey = exported.find(
        (key) => key.type === KeyDataKeyType.RSAPrivateKey,
      )
      expect(privateKey).toBeDefined()
      expect(privateKey?.name).toEqual(keyPairName)
      const password = exported.find(
        (key) => key.type === KeyDataKeyType.Password,
      )
      expect(password).toBeDefined()
      expect(password?.name).toEqual(passwordName)
      const symmetricKey = exported.find(
        (key) => key.type === KeyDataKeyType.SymmetricKey,
      )
      expect(symmetricKey).toBeDefined()
      expect(symmetricKey?.name).toEqual(symmetricKeyName)
    })

    it('should not create duplicates if key name contains another key type', async () => {
      const passwordName = 'testKey.symmetric.password'
      const symmetricKeyName = 'testKey.symmetric'
      await cryptoProvider.addPassword(
        BufferUtil.fromString('am@z1ing'),
        passwordName,
      )
      await cryptoProvider.generateSymmetricKey(symmetricKeyName)

      const exported = await cryptoProvider.exportKeys()
      expect(exported).toHaveLength(2)
      const password = exported.find(
        (key) => key.type === KeyDataKeyType.Password,
      )
      expect(password).toBeDefined()
      expect(password?.name).toEqual(passwordName)
      const symmetricKey = exported.find(
        (key) => key.type === KeyDataKeyType.SymmetricKey,
      )
      expect(symmetricKey).toBeDefined()
      expect(symmetricKey?.name).toEqual(symmetricKeyName)
    })
  })

  describe('RSA crypto using non default key size', () => {
    it('should encrypt with public key then decrypt with private key', async () => {
      const cryptoProvider = new WebSudoCryptoProvider(
        'namespace',
        'servicename',
        undefined,
        4096,
      )
      await cryptoProvider.generateKeyPair('testKey.keyPair')

      const encryptedBuffer = await cryptoProvider.encryptWithPublicKeyName(
        'testKey.keyPair',
        BufferUtil.fromString('data to encrypt'),
      )

      const decryptedBuffer = await cryptoProvider.decryptWithPrivateKey(
        'testKey.keyPair',
        encryptedBuffer,
      )

      const decrypted = BufferUtil.toString(decryptedBuffer)

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
  })

  describe('archive tests', () => {
    jest.setTimeout(15000)
    it('should archive 200 private keys to an insecure archive with binary size less than 400kB by some margin', async () => {
      const keyManager = new DefaultSudoKeyManager(cryptoProvider)

      const promises: Promise<void>[] = []
      for (let i = 0; i < 200; ++i) {
        promises.push(keyManager.generateKeyPair(v4()))
      }
      await Promise.all(promises)

      const archiver = new DefaultSudoKeyArchive(keyManager, {
        excludedKeyTypes: new Set([KeyArchiveKeyType.PublicKey]),
      })
      await archiver.loadKeys()
      const archive = await archiver.archive(undefined)

      expect(archive.byteLength).toBeLessThan(325 * 1024)
    })

    it('in memory store - should be able to have a secure archive created from it that can be reimported', async () => {
      const keyManager = new DefaultSudoKeyManager(cryptoProvider)

      const promises: Promise<void>[] = []
      const names: string[] = []
      for (let i = 0; i < 10; ++i) {
        const name = v4()
        promises.push(keyManager.generateKeyPair(name))
        promises.push(keyManager.generateSymmetricKey(name))
        names.push(name)
      }
      await Promise.all(promises)

      const publicKeySealed: Record<string, ArrayBuffer> = {}
      const symmetricKeySealed: Record<string, ArrayBuffer> = {}
      for (const name of names) {
        publicKeySealed[name] = await keyManager.encryptWithPublicKey(
          name,
          BufferUtil.fromString(name),
        )
        symmetricKeySealed[name] = await keyManager.encryptWithSymmetricKeyName(
          name,
          BufferUtil.fromString(name),
        )
      }

      const archiver = new DefaultSudoKeyArchive(keyManager, {
        excludedKeyTypes: new Set([KeyArchiveKeyType.PublicKey]),
      })
      await archiver.loadKeys()

      const archive = await archiver.archive(BufferUtil.fromString('password'))

      await cryptoProvider.removeAllKeys()

      const unarchiver = new DefaultSudoKeyArchive(keyManager, {
        archiveData: archive,
      })
      await unarchiver.unarchive(BufferUtil.fromString('password'))
      await unarchiver.saveKeys()

      for (const name of names) {
        const privateKeyUnsealed = await keyManager.decryptWithPrivateKey(
          name,
          publicKeySealed[name],
        )
        expect(BufferUtil.toString(privateKeyUnsealed!)).toEqual(name)
        const symmetricKeyUnsealed =
          await keyManager.decryptWithSymmetricKeyName(
            name,
            symmetricKeySealed[name],
          )
        expect(BufferUtil.toString(symmetricKeyUnsealed!)).toEqual(name)
      }
    })

    it('local storage based async store - should be able to have a secure archive created from it that can be reimported', async () => {
      const localStorageCryptoProvider = new WebSudoCryptoProvider(
        'namespace',
        'servicename',
        new LocalStorageStore(window.localStorage),
      )
      const keyManager = new DefaultSudoKeyManager(localStorageCryptoProvider)

      const promises: Promise<void>[] = []
      const names: string[] = []
      for (let i = 0; i < 10; ++i) {
        const name = v4()
        promises.push(keyManager.generateKeyPair(name))
        promises.push(keyManager.generateSymmetricKey(name))
        names.push(name)
      }
      await Promise.all(promises)

      const publicKeySealed: Record<string, ArrayBuffer> = {}
      const symmetricKeySealed: Record<string, ArrayBuffer> = {}
      for (const name of names) {
        publicKeySealed[name] = await keyManager.encryptWithPublicKey(
          name,
          BufferUtil.fromString(name),
        )
        symmetricKeySealed[name] = await keyManager.encryptWithSymmetricKeyName(
          name,
          BufferUtil.fromString(name),
        )
      }

      const archiver = new DefaultSudoKeyArchive(keyManager, {
        excludedKeyTypes: new Set([KeyArchiveKeyType.PublicKey]),
      })
      await archiver.loadKeys()

      const archive = await archiver.archive(BufferUtil.fromString('password'))

      await localStorageCryptoProvider.removeAllKeys()

      const unarchiver = new DefaultSudoKeyArchive(keyManager, {
        archiveData: archive,
      })
      await unarchiver.unarchive(BufferUtil.fromString('password'))
      await unarchiver.saveKeys()

      for (const name of names) {
        const privateKeyUnsealed = await keyManager.decryptWithPrivateKey(
          name,
          publicKeySealed[name],
        )
        expect(BufferUtil.toString(privateKeyUnsealed!)).toEqual(name)
        const symmetricKeyUnsealed =
          await keyManager.decryptWithSymmetricKeyName(
            name,
            symmetricKeySealed[name],
          )
        expect(BufferUtil.toString(symmetricKeyUnsealed!)).toEqual(name)
      }

      await localStorageCryptoProvider.removeAllKeys()
    })

    it('should throw KeyArchivePasswordError if password is incorrect', async () => {
      const keyManager = new DefaultSudoKeyManager(cryptoProvider)

      const promises: Promise<void>[] = []
      const names: string[] = []
      for (let i = 0; i < 10; ++i) {
        const name = v4()
        promises.push(keyManager.generateKeyPair(name))
        promises.push(keyManager.generateSymmetricKey(name))
        names.push(name)
      }
      await Promise.all(promises)

      const publicKeySealed: Record<string, ArrayBuffer> = {}
      const symmetricKeySealed: Record<string, ArrayBuffer> = {}
      for (const name of names) {
        publicKeySealed[name] = await keyManager.encryptWithPublicKey(
          name,
          BufferUtil.fromString(name),
        )
        symmetricKeySealed[name] = await keyManager.encryptWithSymmetricKeyName(
          name,
          BufferUtil.fromString(name),
        )
      }

      const archiver = new DefaultSudoKeyArchive(keyManager, {
        excludedKeyTypes: new Set([KeyArchiveKeyType.PublicKey]),
      })
      await archiver.loadKeys()

      const archive = await archiver.archive(BufferUtil.fromString('password'))

      await cryptoProvider.removeAllKeys()

      const unarchiver = new DefaultSudoKeyArchive(keyManager, {
        archiveData: archive,
      })
      await expect(
        unarchiver.unarchive(BufferUtil.fromString('wrong')),
      ).rejects.toThrow(new KeyArchiveIncorrectPasswordError())
    })
  })
})
