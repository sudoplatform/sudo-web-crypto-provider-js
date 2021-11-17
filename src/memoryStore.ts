import { AsyncStore } from './asyncStore'

/**
 * `AsyncStore` implementation which keeps data in memory.
 */
export class MemoryStore implements AsyncStore {
  data: Partial<Record<string, unknown>> = {}

  async getKeys(): Promise<string[]> {
    return Object.keys(this.data)
  }

  async getItem(key: string): Promise<unknown | null> {
    return this.data[key] ?? null
  }

  async setItem(key: string, value: unknown): Promise<void> {
    this.data[key] = value
  }

  async removeItem(key: string): Promise<void> {
    delete this.data[key]
  }

  async clear(): Promise<void> {
    this.data = {}
  }
}
