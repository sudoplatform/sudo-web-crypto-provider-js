/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Async version of a `Store`
 */
export interface AsyncStore {
  /**
   * Returns the keys of all the key/value pairs in the key store.
   */
  getKeys(): Promise<string[]>

  /**
   * Returns the current value associated with the given key, or null if the
   * given key does not exist in the list associated with the object.
   */
  getItem(key: string): Promise<unknown | null>

  /**
   * Sets the value of the pair identified by key to value, creating a new
   * key/value pair if none existed for key previously.
   */
  setItem(key: string, value: unknown): Promise<void>

  /**
   * Removes the key/value pair with the given key from the list associated
   * with the object, if a key/value pair with the given key exists.
   */
  removeItem(key: unknown): Promise<void>

  /**
   * Empties the list associated with the object of all key/value pairs,
   * if there are any.
   */
  clear(): Promise<void>
}
