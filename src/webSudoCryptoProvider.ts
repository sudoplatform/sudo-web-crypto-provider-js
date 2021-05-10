import { KeyNotFoundError } from './errors'
import { SudoCryptoProvider } from '@sudoplatform/sudo-common'
import {
  PublicKey,
  PublicKeyFormat,
} from '@sudoplatform/sudo-common/lib/sudoKeyManager/publicKey'

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
  publicKey: ArrayBuffer | undefined
  privateKey: ArrayBuffer | undefined
}

export class WebSudoCryptoProvider implements SudoCryptoProvider {
  constructor(namespace: string, serviceName: string) {
    this.#namespace = namespace
    this.#serviceName = serviceName
  }
  private static readonly Constants = {
    ivSize: 16,
    publicKeyEncryptionAlgorithm: 'RSA-OAEP',
    symmetricKeyEncryptionAlgorithm: 'AES-CBC',
    hashingAlgorithm: 'SHA-1',
  }

  #namespace: string
  #serviceName: string

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
      throw new KeyNotFoundError()
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
        length: 256,
      },
      true,
      ['encrypt', 'decrypt'],
    )

    const formattedKey = await crypto.subtle.exportKey(KeyFormat.Raw, cryptoKey)

    this.#symmetricKeys[name] = formattedKey
  }

  public async deleteKeyPair(name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    delete this.#keyPairs[name]
    Promise.resolve()
  }

  public async addPrivateKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    this.#keyPairs[name] = { privateKey: key, publicKey: undefined }
    Promise.resolve()
  }

  public async getPrivateKey(name: string): Promise<ArrayBuffer | undefined> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    return Promise.resolve(this.#keyPairs[name]?.privateKey)
  }

  public async addPublicKey(key: ArrayBuffer, name: string): Promise<void> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    this.#keyPairs[name] = { privateKey: undefined, publicKey: key }
    Promise.resolve()
  }

  public async getPublicKey(name: string): Promise<PublicKey | undefined> {
    name = this.createKeySearchTerm(name, KeyType.KeyPair)
    const key = this.#keyPairs[name]?.publicKey
    if (!key) {
      return undefined
    } else {
      return {
        keyData: key,
        // Format for public keys created by web sudo crypto is SPKI
        keyFormat: PublicKeyFormat.SPKI,
      }
    }
  }

  public async removeAllKeys(): Promise<void> {
    this.#passwords = {}
    this.#symmetricKeys = {}
    this.#keyPairs = {}
    return Promise.resolve()
  }

  public createRandomData(size: number): ArrayBuffer {
    const buffer = new ArrayBuffer(size)
    crypto.getRandomValues(new Uint8Array(buffer))
    return buffer
  }

  public async encryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    const key = this.#symmetricKeys[name]
    if (!key) {
      throw new KeyNotFoundError()
    }
    return await this.encryptWithSymmetricKey(key, data, iv)
  }

  public async decryptWithSymmetricKeyName(
    name: string,
    data: ArrayBuffer,
    iv?: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    name = this.createKeySearchTerm(name, KeyType.Symmetric)
    const key = this.#symmetricKeys[name]
    if (!key) {
      throw new KeyNotFoundError()
    }
    return await this.decryptWithSymmetricKey(key, data, iv)
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

    const formattedPublicKey = await crypto.subtle.importKey(
      KeyFormat.Spki,
      publicKey,
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        hash: { name: WebSudoCryptoProvider.Constants.hashingAlgorithm },
      },
      true,
      ['encrypt'],
    )

    const encrypted = await crypto.subtle.encrypt(
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
      },
      formattedPublicKey,
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

    const formattedPrivateKey = await crypto.subtle.importKey(
      KeyFormat.Pkcs8,
      privateKey,
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
        hash: { name: WebSudoCryptoProvider.Constants.hashingAlgorithm },
      },
      true,
      ['decrypt'],
    )

    const decrypted = await crypto.subtle.decrypt(
      {
        name: WebSudoCryptoProvider.Constants.publicKeyEncryptionAlgorithm,
      },
      formattedPrivateKey,
      data,
    )

    return decrypted
  }

  public async generateHash(data: ArrayBuffer): Promise<ArrayBuffer> {
    return await crypto.subtle.digest(
      WebSudoCryptoProvider.Constants.hashingAlgorithm,
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
        hash: { name: WebSudoCryptoProvider.Constants.hashingAlgorithm },
      },
      true,
      ['encrypt', 'decrypt'],
    )

    const publicKeyBits = await crypto.subtle.exportKey(
      KeyFormat.Spki,
      keyPair.publicKey,
    )

    const privateKeyBits = await crypto.subtle.exportKey(
      KeyFormat.Pkcs8,
      keyPair.privateKey,
    )

    const newKeyPair = {
      privateKey: privateKeyBits,
      publicKey: publicKeyBits,
    }

    this.#keyPairs[name] = newKeyPair
  }

  private createKeySearchTerm(name: string, type: KeyType): string {
    const prefix = this.#namespace
    return `${prefix}${prefix.length ? '.' : ''}${name}.${type}`
  }
}
