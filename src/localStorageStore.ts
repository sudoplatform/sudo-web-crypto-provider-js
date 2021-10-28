import { AsyncStore } from './asyncStore'

/**
 * A local storage based implementation of an AsyncStore for testing purposes only
 */
export class LocalStorageStore implements AsyncStore {
  constructor(private storageArea = window.localStorage) {}

  async getItem(key: string): Promise<unknown | null> {
    return this.storageArea.getItem(key)
  }

  async setItem(key: string, value: unknown): Promise<void> {
    this.storageArea.setItem(key, value as string)
  }

  async removeItem(key: string): Promise<void> {
    this.storageArea.removeItem(key)
  }

  async clear(): Promise<void> {
    this.storageArea.clear()
  }
}
