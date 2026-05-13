// src/core/rate-limiter.js
'use strict';

/**
 * Adaptive rate limiter to avoid triggering IDS alerts.
 * Enforces per-second request budgets using a token bucket approach.
 */
class RateLimiter {
  #requestsPerSecond;
  #tokens;
  #lastRefill;
  #queue;
  #processing;
  #timer;
  #destroyed;

  constructor(options = {}) {
    this.#requestsPerSecond = options.requestsPerSecond || 100;
    this.#tokens = this.#requestsPerSecond;
    this.#lastRefill = Date.now();
    this.#queue = [];
    this.#processing = false;
    this.#timer = null;
    this.#destroyed = false;
  }

  /**
   * Acquire a token to proceed with a request.
   * Blocks until a token is available.
   * Rejects if the limiter has been destroyed.
   */
  async acquire() {
    if (this.#destroyed) {
      throw new Error('RateLimiter has been destroyed');
    }

    return new Promise((resolve) => {
      this.#queue.push(resolve);
      this.#processQueue();
    });
  }

  /**
   * Release a token back to the pool.
   * Called after request completion.
   */
  release() {
    if (this.#destroyed) return;
    this.#refillTokens();
    this.#tokens = Math.min(this.#tokens + 1, this.#requestsPerSecond);
    this.#processQueue();
  }

  /**
   * Destroy the rate limiter, clearing any pending timers.
   * Resolves all queued acquires to prevent hanging promises.
   */
  destroy() {
    this.#destroyed = true;
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    // Resolve any queued promises so callers don't hang
    while (this.#queue.length > 0) {
      const resolve = this.#queue.shift();
      resolve();
    }
  }

  /**
   * Process the queue of pending acquires.
   * @private
   */
  #processQueue() {
    if (this.#processing || this.#destroyed) return;
    this.#processing = true;

    while (this.#queue.length > 0) {
      this.#refillTokens();

      if (this.#tokens > 0) {
        this.#tokens--;
        const resolve = this.#queue.shift();
        resolve();
      } else {
        // No tokens available, schedule next check
        // Use clearTimeout for cleanup in destroy()
        this.#timer = setTimeout(() => {
          this.#timer = null;
          this.#processQueue();
        }, 10);
        break;
      }
    }

    this.#processing = false;
  }

  /**
   * Refill tokens based on elapsed time.
   * @private
   */
  #refillTokens() {
    const now = Date.now();
    const elapsedMs = now - this.#lastRefill;
    const tokensToAdd = Math.floor((elapsedMs / 1000) * this.#requestsPerSecond);

    if (tokensToAdd > 0) {
      this.#tokens = Math.min(this.#tokens + tokensToAdd, this.#requestsPerSecond);
      this.#lastRefill = now;
    }
  }
}

module.exports = { RateLimiter };