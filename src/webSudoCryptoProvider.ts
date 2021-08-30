import {
  KeyData,
  KeyDataKeyFormat,
  KeyDataKeyType,
  PublicKey,
  PublicKeyFormat,
  SudoCryptoProvider,
  SudoCryptoProviderDefaults,
} from '@sudoplatform/sudo-common'

import { KeyNotFoundError } from './errors'

// eslint-disable-next-line @typescript-eslint/no-var-requires

enum KeyType {
  Symmetric = 'symmetric',
  Password = 'password',
  KeyPair = 'keyPair',
}

export enum KeyFormat {
  Raw = 'raw',
  Jwk = 'jwk', // public or private
  Spki = 'spki', // public only
  Pkcs8 = 'pkcs8', // private only
}

export interface KeyPair {
  publicKey: CryptoKey | undefined
  privateKey: CryptoKey | undefined
}

export class WebSudoCryptoProvider implements SudoCryptoProvider {
  constructor(namespace: string, serviceName: string) {
    this.#namespace = namespace
    this.#serviceName = serviceName
  }
  private static readonly Constants = {
    ivSize: SudoCryptoProviderDefaults.aesIVSize,
    publicKeyEncryptionAlgorithm: 'RSA-OAEP',
    symmetricKeyEncryptionAlgorithm: 'AES-CBC',
    symmetricKeySize: SudoCryptoProviderDefaults.aesKeySize,
    publicKeyEncryptionHashingAlgorithm: 'SHA-1',
    pbkdfAlgorithm: 'PBKDF2',
    pbkdfHashingAlgorithm: 'SHA-256',
    pbkdfDefaultRounds: SudoCryptoProviderDefaults.pbkdfRounds,
  }

  readonly #namespace: string
  readonly #serviceName: string

  #passwords: Record<string, ArrayBuffer> = {}
  #symmetricKeys: Record<string, ArrayBuffer> = {}
  #keyPairs: Record<string, KeyPair> = {}

  public getNamespace(): string {
    return this.#namespace
  }

  public getServiceName(): string {
    return this.#serviceName
  }

  public async addPassword(password: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Password)
    this.#passwords[name] = password
    return Promise.resolve()
  }

  public async getPassword(name: string): Promise<ArrayBuffer | undefined> {
    name = this.createKeySearchTerm(name, KeyType.Password)
    return Promise.resolve(this.#passwords[name])
  }

  public async deletePassword(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Password)
    delete this.#passwords[name]
    return Promise.resolve()
  }

  public async updatePassword(
    password: ArrayBuffer,
    name: string,
  ): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Password)
    if (this.#passwords[name]) {
      this.#passwords[name] = password
    } else {
      return Promise.reject(new KeyNotFoundError())
    }
    return Promise.resolve()
  }

  public async addSymmetricKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    this.#symmetricKeys[name] = key
    return Promise.resolve()
  }

  public async getSymmetricKey(name: string): Promise<ArrayBuffer | undefined> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    return Promise.resolve(this.#symmetricKeys[name])
  }

  public async deleteSymmetricKey(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    delete this.#symmetricKeys[name]
    return Promise.resolve()
  }

  public async generateSymmetricKey(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    const cryptoKey = await crypto.subtle.generateKey(
      {
        name: WebSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
        length: WebSudoCryptoProvider.Constants.symmetricKeySize,
      },
      true,
      ['encrypt', 'decrypt'],
    )

    const formattedKey = await crypto.subtle.exportKey(KeyFormat.Raw, cryptoKey)

    this.#symmetricKeys[name] = formattedKey
  }

  public async generateSymmetricKeyFromPassword(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    options?: { rounds?: number },
  ): Promise<ArrayBuffer> {
    const rounds =
      options?.rounds ?? WebSudoCryptoProvider.Constants.pbkdfDefaultRounds

    const symmetricKey = await crypto.subtle.deriveBits(
      {
        name: WebSudoCryptoProvider.Constants.pbkdfAlgorithm,
        salt,
        iterations: rounds,
        hash: 'SHA-256',
      },
      await crypto.subtle.importKey(
        'raw',
        password,
        WebSudoCryptoProvider.Constants.pbkdfAlgorithm,
        false,
        ['deriveBits', 'deriveKey'],
      ),
      WebSudoCryptoProvider.Constants.symmetricKeySize,
    )

    return symmetricKey
  }

  public async deleteKeyPair(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    delete this.#keyPairs[name]
    Promise.resolve()
  }

  public async addPrivateKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)

    const privateKey = await crypto.subtle.importKey(
      KeyFormat.Pkcs8,
      key,
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        hash: {
          name: WebSudoCryptoProvider.Constants
            .publicKeyEncryptionHashingAlgorithm,
        },
      },
      true,
      ['decrypt'],
    )

    const keyPair = this.#keyPairs[name]
    if (keyPair) {
      keyPair.privateKey = privateKey
      this.#keyPairs[name] = keyPair
    } else {
      this.#keyPairs[name] = { privateKey: privateKey, publicKey: undefined }
    }
  }

  public async getPrivateKey(name: string): Promise<ArrayBuffer | undefined> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    const key = this.#keyPairs[name]?.privateKey
    if (!key) {
      return
    } else {
      const privateKeyBits = await crypto.subtle.exportKey(KeyFormat.Pkcs8, key)

      return privateKeyBits
    }
  }

  public async addPublicKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)

    const publicKey = await crypto.subtle.importKey(
      KeyFormat.Spki,
      key,
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        hash: {
          name: WebSudoCryptoProvider.Constants
            .publicKeyEncryptionHashingAlgorithm,
        },
      },
      true,
      ['encrypt'],
    )

    const keyPair = this.#keyPairs[name]
    if (keyPair) {
      keyPair.publicKey = publicKey
      this.#keyPairs[name] = keyPair
    } else {
      this.#keyPairs[name] = { privateKey: undefined, publicKey }
    }
  }

  public async getPublicKey(name: string): Promise<PublicKey | undefined> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    const key = this.#keyPairs[name]?.publicKey
    if (!key) {
      return
    } else {
      const publicKeyBits = await crypto.subtle.exportKey(KeyFormat.Spki, key)

      return {
        keyData: publicKeyBits,
        // Format for public keys created by web sudo crypto is SPKI
        keyFormat: PublicKeyFormat.SPKI,
      }
    }
  }

  public removeAllKeys(): Promise<void> {
    this.#passwords = {}
    this.#symmetricKeys = {}
    this.#keyPairs = {}
    return Promise.resolve()
  }

  public generateRandomData(size: number): Promise<ArrayBuffer> {
    const buffer = new ArrayBuffer(size)
    crypto.getRandomValues(new Uint8Array(buffer))
    return Promise.resolve(buffer)
  }

  public encryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    const key = this.#symmetricKeys[name]
    if (!key) {
      return Promise.reject(new KeyNotFoundError())
    }
    return this.encryptWithSymmetricKey(key, data, iv)
  }

  public decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    const key = this.#symmetricKeys[name]
    if (!key) {
      return Promise.reject(new KeyNotFoundError())
    }
    return this.decryptWithSymmetricKey(key, data, iv)
  }

  public async encryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (!iv) {
      iv = new ArrayBuffer(WebSudoCryptoProvider.Constants.ivSize)
    }
    const secretKey = await crypto.subtle.importKey(
      'raw',
      key,
      WebSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
      false,
      ['encrypt'],
    )
    const encrypted = await crypto.subtle.encrypt(
      {
        name: WebSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
        iv,
      },
      secretKey,
      data,
    )
    return encrypted
  }

  public async decryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (!iv) {
      iv = new ArrayBuffer(WebSudoCryptoProvider.Constants.ivSize)
    }
    const secretKey = await crypto.subtle.importKey(
      'raw',
      key,
      WebSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
      false,
      ['decrypt'],
    )
    const decrypted = await crypto.subtle.decrypt(
      {
        name: WebSudoCryptoProvider.Constants.symmetricKeyEncryptionAlgorithm,
        iv,
      },
      secretKey,
      data,
    )
    return decrypted
  }

  public async encryptWithPublicKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    const publicKey = this.#keyPairs[name]?.publicKey
    if (!publicKey) {
      throw new KeyNotFoundError()
    }

    const encrypted = await crypto.subtle.encrypt(
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
      },
      publicKey,
      data,
    )

    return encrypted
  }

  public async decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    const privateKey = this.#keyPairs[name]?.privateKey
    if (!privateKey) {
      throw new KeyNotFoundError()
    }

    const decrypted = await crypto.subtle.decrypt(
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
      },
      privateKey,
      data,
    )

    return decrypted
  }

  public generateHash(data: ArrayBuffer): Promise<ArrayBuffer> {
    return crypto.subtle.digest(
      WebSudoCryptoProvider.Constants.publicKeyEncryptionHashingAlgorithm,
      data,
    )
  }

  public async generateKeyPair(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    const keyPair = await crypto.subtle.generateKey(
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {
          name: WebSudoCryptoProvider.Constants
            .publicKeyEncryptionHashingAlgorithm,
        },
      },
      true,
      ['encrypt', 'decrypt'],
    )

    this.#keyPairs[name] = {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    }
  }

  public async exportKeys(): Promise<KeyData[]> {
    const keys: KeyData[] = []
    const entries = Object.entries(this.#keyPairs)
    for (const [k, v] of entries) {
      const name = this.recoverKeyName(k, KeyType.KeyPair)
      if (v.privateKey) {
        const privateKeyBits = await crypto.subtle.exportKey(
          KeyFormat.Pkcs8,
          v.privateKey,
        )

        keys.push({
          name,
          namespace: this.#namespace,
          data: privateKeyBits,
          type: KeyDataKeyType.RSAPrivateKey,
          format: KeyDataKeyFormat.PKCS8,
        })
      }
      if (v.publicKey) {
        const publicKeyBits = await crypto.subtle.exportKey(
          KeyFormat.Spki,
          v.publicKey,
        )

        keys.push({
          name,
          namespace: this.#namespace,
          data: publicKeyBits,
          type: KeyDataKeyType.RSAPublicKey,
          format: KeyDataKeyFormat.SPKI,
        })
      }
    }

    Object.entries(this.#passwords).forEach(([k, v]) => {
      keys.push({
        name: this.recoverKeyName(k, KeyType.Password),
        namespace: this.#namespace,
        data: v,
        type: KeyDataKeyType.Password,
        format: KeyDataKeyFormat.Raw,
      })
    })

    Object.entries(this.#symmetricKeys).forEach(([k, v]) => {
      keys.push({
        name: this.recoverKeyName(k, KeyType.Symmetric),
        namespace: this.#namespace,
        data: v,
        type: KeyDataKeyType.SymmetricKey,
        format: KeyDataKeyFormat.Raw,
      })
    })

    return keys
  }

  private createKeySearchTerm(name: string, type: KeyType): string {
    const prefix = this.#namespace
    return `${prefix}${prefix.length ? '.' : ''}${name}.${type}`
  }

  private recoverKeyName(keySearchTerm: string, type: KeyType): string {
    const prefixLength = this.#namespace.length ? this.#namespace.length + 1 : 0
    return keySearchTerm.substring(
      prefixLength,
      keySearchTerm.length - type.length - 1,
    )
  }
}
