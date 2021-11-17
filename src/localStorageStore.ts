import { AsyncStore } from './asyncStore'

/**
 * A local storage based implementation of an AsyncStore for testing purposes only
 */
export class LocalStorageStore implements AsyncStore {
  constructor(private storage = window.localStorage) {}

  async getKeys(): Promise<string[]> {
    return Object.keys(this.storage)
  }

  async getItem(key: string): Promise<unknown | null> {
    return this.storage.getItem(key)
  }

  async setItem(key: string, value: unknown): Promise<void> {
    this.storage.setItem(key, value as string)
  }

  async removeItem(key: string): Promise<void> {
    this.storage.removeItem(key)
  }

  async clear(): Promise<void> {
    this.storage.clear()
  }
}
