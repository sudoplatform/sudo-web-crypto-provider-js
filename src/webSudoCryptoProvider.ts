/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AsymmetricEncryptionOptions,
  Base64,
  Buffer as BufferUtil,
  EncryptionAlgorithm,
  KeyData,
  KeyDataKeyFormat,
  KeyDataKeyType,
  PublicKey,
  PublicKeyFormat,
  SignatureAlgorithm,
  SignatureOptions,
  SudoCryptoProvider,
  SudoCryptoProviderDefaults,
  SymmetricEncryptionOptions,
  UnrecognizedAlgorithmError,
} from '@sudoplatform/sudo-common'
import { AsyncStore } from './asyncStore'
import { KeyNotFoundError } from './errors'
import { MemoryStore } from './memoryStore'

// eslint-disable-next-line @typescript-eslint/no-var-requires

enum KeyType {
  Symmetric = 'symmetric',
  Password = 'password',
  PrivateKey = 'privateKey',
  PublicKey = 'publicKey',
}

export enum KeyFormat {
  Raw = 'raw',
  Jwk = 'jwk', // public or private
  Spki = 'spki', // public only
  Pkcs8 = 'pkcs8', // private only
}

export class WebSudoCryptoProvider implements SudoCryptoProvider {
  constructor(
    namespace: string,
    serviceName: string,
    asyncStore?: AsyncStore,
    rsaKeySize?: number,
  ) {
    this.#namespace = namespace
    this.#serviceName = serviceName
    this.#store = asyncStore ?? new MemoryStore()
    this.#rsaKeySize = rsaKeySize ?? WebSudoCryptoProvider.Constants.rsaKeySize
  }
  private static readonly Constants = {
    ivSize: SudoCryptoProviderDefaults.aesIVSize,
    publicKeyEncryptionAlgorithm: 'RSA-OAEP',
    symmetricKeyEncryptionAlgorithm: 'AES-CBC',
    symmetricKeySize: SudoCryptoProviderDefaults.aesKeySize,
    rsaKeySize: SudoCryptoProviderDefaults.rsaKeySize,
    publicKeyEncryptionHashingAlgorithm: 'SHA-1',
    pbkdfAlgorithm: 'PBKDF2',
    pbkdfHashingAlgorithm: 'SHA-256',
    pbkdfDefaultRounds: SudoCryptoProviderDefaults.pbkdfRounds,
    signatureGenerationAlgorithm: 'RSASSA-PKCS1-v1_5',
    signatureHashingAlgorithm: 'SHA-256',
  }

  /* eslint-disable tree-shaking/no-side-effects-in-initialization */
  readonly #namespace: string
  readonly #serviceName: string
  readonly #rsaKeySize: number
  #store: AsyncStore
  /* eslint-enable tree-shaking/no-side-effects-in-initialization */

  public getNamespace(): string {
    return this.#namespace
  }

  public getServiceName(): string {
    return this.#serviceName
  }

  public async addPassword(password: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Password)
    await this.#store.setItem(name, Base64.encode(password))
    return Promise.resolve()
  }

  async getPassword(name: string): Promise<ArrayBuffer | undefined> {
    name = this.createKeySearchTerm(name, KeyType.Password)
    const pwd = await this.#store.getItem(name)
    const password =
      pwd && typeof pwd === 'string' ? Base64.decode(pwd) : undefined
    return Promise.resolve(password)
  }

  public async deletePassword(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Password)
    await this.#store.removeItem(name)
    return Promise.resolve()
  }

  public async updatePassword(
    password: ArrayBuffer,
    name: string,
  ): Promise<void> {
    const pwd = await this.getPassword(name)
    if (pwd) {
      await this.deletePassword(name)
      await this.addPassword(password, name)
    } else {
      return Promise.reject(new KeyNotFoundError())
    }
    return Promise.resolve()
  }

  public async addSymmetricKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    await this.#store.setItem(name, Base64.encode(key))
    return Promise.resolve()
  }

  public async getSymmetricKey(name: string): Promise<ArrayBuffer | undefined> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    const key = await this.#store.getItem(name)
    const symmetricKey =
      key && typeof key === 'string' ? Base64.decode(key) : undefined
    return Promise.resolve(symmetricKey)
  }

  public async doesSymmetricKeyExist(name: string): Promise<boolean> {
    return (await this.getSymmetricKey(name)) !== undefined
  }

  public async deleteSymmetricKey(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    await this.#store.removeItem(name)
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

    await this.#store.setItem(name, Base64.encode(formattedKey))
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
        salt: new Uint8Array(salt),
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
    const privateKeyName = this.createKeySearchTerm(name, KeyType.PrivateKey)
    const publicKeyName = this.createKeySearchTerm(name, KeyType.PublicKey)
    await this.#store.removeItem(privateKeyName)
    await this.#store.removeItem(publicKeyName)
  }

  public async deletePublicKey(name: string): Promise<void> {
    const publicKeyName = this.createKeySearchTerm(name, KeyType.PublicKey)
    await this.#store.removeItem(publicKeyName)
  }

  public async generateSignatureWithPrivateKey(
    name: string,
    data: ArrayBuffer,
    options?: SignatureOptions,
  ): Promise<ArrayBuffer> {
    const signatureAlgorithm =
      options?.algorithm ?? SignatureAlgorithm.RsaPkcs15Sha256
    const { signatureGenerationAlgorithm, signatureHashingAlgorithm } =
      this.signatureAlgorithms(signatureAlgorithm)

    const key = await this.getPrivateKey(name)
    if (!key) {
      return Promise.reject(new KeyNotFoundError())
    }
    const privateKey = await crypto.subtle.importKey(
      KeyFormat.Pkcs8,
      key,
      {
        name: signatureGenerationAlgorithm,
        hash: {
          name: signatureHashingAlgorithm,
        },
      },
      true,
      ['sign'],
    )
    return await crypto.subtle.sign(
      signatureGenerationAlgorithm,
      privateKey,
      data,
    )
  }

  public async verifySignatureWithPublicKey(
    name: string,
    data: ArrayBuffer,
    signature: ArrayBuffer,
    options?: SignatureOptions,
  ): Promise<boolean> {
    const signatureAlgorithm =
      options?.algorithm ?? SignatureAlgorithm.RsaPkcs15Sha256
    const { signatureGenerationAlgorithm, signatureHashingAlgorithm } =
      this.signatureAlgorithms(signatureAlgorithm)

    name = this.createKeySearchTerm(name, KeyType.PublicKey)
    const key = await this.#store.getItem(name)
    if (!key) {
      return Promise.reject(new KeyNotFoundError())
    }
    const keyData = Base64.decode(key as string)

    const publicKey = await crypto.subtle.importKey(
      KeyFormat.Spki,
      keyData,
      {
        name: signatureGenerationAlgorithm,
        hash: {
          name: signatureHashingAlgorithm,
        },
      },
      true,
      ['verify'],
    )

    return await crypto.subtle.verify(
      signatureGenerationAlgorithm,
      publicKey,
      signature,
      data,
    )
  }

  public async addPrivateKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.PrivateKey)
    await this.#store.setItem(name, Base64.encode(key))
  }

  public async getPrivateKey(name: string): Promise<ArrayBuffer | undefined> {
    name = this.createKeySearchTerm(name, KeyType.PrivateKey)
    const key = await this.#store.getItem(name)
    if (!key) {
      return
    } else {
      return Base64.decode(key as string)
    }
  }

  public async doesPrivateKeyExist(name: string): Promise<boolean> {
    return (await this.getPrivateKey(name)) !== undefined
  }

  public async addPublicKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.PublicKey)
    await this.#store.setItem(name, Base64.encode(key))
  }

  public async getPublicKey(name: string): Promise<PublicKey | undefined> {
    name = this.createKeySearchTerm(name, KeyType.PublicKey)
    const key = await this.#store.getItem(name)
    if (!key) {
      return
    } else {
      const publicKeyBits = Base64.decode(key as string)
      return {
        keyData: publicKeyBits,
        // Format for public keys created by web sudo crypto is SPKI
        keyFormat: PublicKeyFormat.SPKI,
      }
    }
  }

  public async removeAllKeys(): Promise<void> {
    await this.#store.clear()
    return Promise.resolve()
  }

  public generateRandomData(size: number): Promise<ArrayBuffer> {
    const buffer = new ArrayBuffer(size)
    crypto.getRandomValues(new Uint8Array(buffer))
    return Promise.resolve(buffer)
  }

  public async encryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    const key = await this.#store.getItem(name)
    if (!key) {
      return Promise.reject(new KeyNotFoundError())
    }
    const keyData = Base64.decode(key as string)
    return this.encryptWithSymmetricKey(keyData, data, ivOrOptions)
  }

  public async decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)

    const key = await this.#store.getItem(name)
    if (!key) {
      return Promise.reject(new KeyNotFoundError())
    }
    const keyData = Base64.decode(key as string)
    return this.decryptWithSymmetricKey(keyData, data, ivOrOptions)
  }

  public async encryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    const options = this.symmetricEncryptionOptions(ivOrOptions)

    const secretKey = await crypto.subtle.importKey(
      'raw',
      key,
      options.algorithmName,
      false,
      ['encrypt'],
    )

    const encrypted = await crypto.subtle.encrypt(
      {
        name: options.algorithmName,
        iv: new Uint8Array(options.iv),
        tagLength: options.algorithmName == 'AES-GCM' ? 128 : undefined,
      },
      secretKey,
      data,
    )

    return encrypted
  }

  public async decryptWithSymmetricKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    const options = this.symmetricEncryptionOptions(ivOrOptions)

    const secretKey = await crypto.subtle.importKey(
      'raw',
      key,
      options.algorithmName,
      false,
      ['decrypt'],
    )
    const decrypted = await crypto.subtle.decrypt(
      {
        name: options.algorithmName,
        iv: new Uint8Array(options.iv),
      },
      secretKey,
      data,
    )

    return decrypted
  }

  public async encryptWithPublicKey(
    name: string,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  public async encryptWithPublicKey(
    key: ArrayBuffer,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer>

  public async encryptWithPublicKey(
    key: unknown,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    if (typeof key === 'string') {
      key = this.createKeySearchTerm(key, KeyType.PublicKey)
      const keyValue = await this.#store.getItem(key as string)
      if (!keyValue) {
        return Promise.reject(new KeyNotFoundError())
      }
      const keyData = Base64.decode(keyValue as string)
      return await this.encryptWithPublicKeyData(keyData, data, options)
    } else {
      return await this.encryptWithPublicKeyData(
        key as ArrayBuffer,
        data,
        options,
      )
    }
  }

  private async encryptWithPublicKeyData(
    key: ArrayBuffer,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
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

    const algorithmName = this.cryptoAlgorithmName(
      options?.algorithm ?? EncryptionAlgorithm.RsaOaepSha1,
    )

    const encrypted = await crypto.subtle.encrypt(
      {
        name: algorithmName,
      },
      publicKey,
      data,
    )

    return encrypted
  }

  public async decryptWithPrivateKey(
    name: string,
    data: ArrayBuffer,
    options?: AsymmetricEncryptionOptions,
  ): Promise<ArrayBuffer> {
    const key = await this.getPrivateKey(name)
    if (!key) {
      return Promise.reject(new KeyNotFoundError())
    }

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

    const algorithmName = this.cryptoAlgorithmName(
      options?.algorithm ?? EncryptionAlgorithm.RsaOaepSha1,
    )

    const decrypted = await crypto.subtle.decrypt(
      {
        name: algorithmName,
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
    const keyPair = await crypto.subtle.generateKey(
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        modulusLength: this.#rsaKeySize,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {
          name: WebSudoCryptoProvider.Constants
            .publicKeyEncryptionHashingAlgorithm,
        },
      },
      true,
      ['encrypt', 'decrypt'],
    )

    const privateKeyBits = await crypto.subtle.exportKey(
      KeyFormat.Pkcs8,
      keyPair.privateKey,
    )
    await this.addPrivateKey(privateKeyBits, name)

    const publicKeyBits = await crypto.subtle.exportKey(
      KeyFormat.Spki,
      keyPair.publicKey,
    )
    await this.addPublicKey(publicKeyBits, name)

    return Promise.resolve()
  }

  public async exportKeys(): Promise<KeyData[]> {
    const keys: KeyData[] = []

    const storeKeys = await this.#store.getKeys()
    for (const k of storeKeys) {
      const v = await this.#store.getItem(k)

      if (k.includes(KeyType.PrivateKey)) {
        keys.push({
          name: this.recoverKeyName(k, KeyType.PrivateKey),
          namespace: this.#namespace,
          data: Base64.decode(v as string),
          type: KeyDataKeyType.RSAPrivateKey,
          format: KeyDataKeyFormat.PKCS8,
        })
      }

      if (k.includes(KeyType.PublicKey)) {
        keys.push({
          name: this.recoverKeyName(k, KeyType.PublicKey),
          namespace: this.#namespace,
          data: Base64.decode(v as string),
          type: KeyDataKeyType.RSAPublicKey,
          format: KeyDataKeyFormat.SPKI,
        })
      }

      if (k.includes(KeyType.Password)) {
        keys.push({
          name: this.recoverKeyName(k, KeyType.Password),
          namespace: this.#namespace,
          data: Base64.decode(v as string),
          type: KeyDataKeyType.Password,
          format: KeyDataKeyFormat.Raw,
        })
      }

      if (k.includes(KeyType.Symmetric)) {
        keys.push({
          name: this.recoverKeyName(k, KeyType.Symmetric),
          namespace: this.#namespace,
          data: Base64.decode(v as string),
          type: KeyDataKeyType.SymmetricKey,
          format: KeyDataKeyFormat.Raw,
        })
      }
    }
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

  cryptoAlgorithmName = (algorithm: EncryptionAlgorithm): string => {
    switch (algorithm) {
      case EncryptionAlgorithm.AesCbcPkcs7Padding:
        return 'AES-CBC'
      case EncryptionAlgorithm.AesGcmNoPadding:
        return 'AES-GCM'
      case EncryptionAlgorithm.RsaOaepSha1:
        return 'RSA-OAEP'
      default:
        throw new UnrecognizedAlgorithmError()
    }
  }

  signatureAlgorithms = (
    algorithm: SignatureAlgorithm,
  ): {
    signatureGenerationAlgorithm: string
    signatureHashingAlgorithm: string
  } => {
    switch (algorithm) {
      case SignatureAlgorithm.RsaPkcs15Sha256:
        return {
          signatureGenerationAlgorithm: 'RSASSA-PKCS1-v1_5',
          signatureHashingAlgorithm: 'SHA-256',
        }
      default:
        throw new UnrecognizedAlgorithmError()
    }
  }

  symmetricEncryptionOptions = (
    ivOrOptions?: ArrayBuffer | SymmetricEncryptionOptions,
  ): { iv: ArrayBuffer; algorithmName: string } => {
    const options = BufferUtil.isArrayBuffer(ivOrOptions)
      ? { iv: ivOrOptions }
      : (ivOrOptions ?? {})
    options.iv ??= new ArrayBuffer(WebSudoCryptoProvider.Constants.ivSize)
    options.algorithm ??= EncryptionAlgorithm.AesCbcPkcs7Padding

    const algorithmName = this.cryptoAlgorithmName(options.algorithm)

    return { iv: options.iv, algorithmName }
  }
}
