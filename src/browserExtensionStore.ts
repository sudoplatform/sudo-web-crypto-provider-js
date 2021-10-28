import { AsyncStore } from './asyncStore'

/**
 * Typed implementation of and AsynStore that is backed by a browser
 * extension storage area.
 */
export class BrowserExtensionStore<Schema> implements AsyncStore {
  private keyPrefix

  constructor(namesace = '', private storageArea = browser.storage.local) {
    this.keyPrefix = namesace ? namesace + '__' : ''
  }

  async getItem<K extends keyof Schema & string>(
    key: K,
  ): Promise<Schema[K] | null> {
    const namespacedKey = this.keyPrefix + key
    const record = await this.storageArea.get({
      [namespacedKey]: null,
    })
    return (record[namespacedKey] as Schema[K]) ?? null
  }

  async setItem<K extends keyof Schema & string>(
    key: K,
    value: Schema[K] | null,
  ): Promise<void> {
    if (value === null) {
      await this.removeItem(key)
    } else {
      const namespacedKey = this.keyPrefix + key
      await this.storageArea.set({ [namespacedKey]: value })
    }
  }

  async removeItem<K extends keyof Schema & string>(key: K): Promise<void> {
    const namespacedKey = this.keyPrefix + key
    await this.storageArea.remove(namespacedKey)
  }

  async clear(): Promise<void> {
    const data = await this.storageArea.get()

    const keysToClear = Object.keys(data).filter((key) =>
      key.startsWith(this.keyPrefix),
    )
    for (const key of keysToClear) {
      await this.storageArea.remove(key)
    }
  }
}
