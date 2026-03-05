import type { SecondaryStorage } from "@better-auth/core/db";
import type { NonceStore } from "@slicekit/erc8128";

interface VerificationAdapter {
	findVerificationValue(identifier: string): Promise<{
		id: string;
		identifier: string;
		value: string;
		expiresAt: Date;
	} | null>;
	createVerificationValue(data: {
		identifier: string;
		value: string;
		expiresAt: Date;
	}): Promise<unknown>;
}

const NONCE_KEY_PREFIX = "erc8128:nonce:";

/**
 * NonceStore backed by `secondaryStorage` (e.g. Redis).
 *
 * Uses `get`/`set` with TTL for atomic-enough nonce consumption.
 * The race window (`get` → `set`) is identical to the DB adapter path
 * (`find` → `create`), and nonces include high-entropy random components
 * so legitimate collisions are effectively impossible.
 */
export function createSecondaryStorageNonceStore(
	storage: SecondaryStorage,
): NonceStore {
	return {
		async consume(key: string, ttlSeconds: number): Promise<boolean> {
			const identifier = `${NONCE_KEY_PREFIX}${key}`;
			try {
				const existing = await storage.get(identifier);
				if (existing) {
					return false;
				}
				await storage.set(identifier, "1", ttlSeconds);
				return true;
			} catch {
				return false;
			}
		},
	};
}

/**
 * Dual-write NonceStore: consumes from both DB and secondaryStorage.
 * Both must succeed for the nonce to be considered consumed.
 * Reads from secondaryStorage first (fast path), falls back to DB.
 */
export function createDualNonceStore(
	dbStore: NonceStore,
	ssStore: NonceStore,
): NonceStore {
	return {
		async consume(key: string, ttlSeconds: number): Promise<boolean> {
			// Check secondaryStorage first (fast)
			const ssResult = await ssStore.consume(key, ttlSeconds);
			if (!ssResult) {
				return false; // Already consumed in SS
			}
			// Also consume in DB for durability
			const dbResult = await dbStore.consume(key, ttlSeconds);
			return dbResult;
		},
	};
}

export function createMemoryNonceStore(): NonceStore {
	const fallback = new Map<string, number>();

	const consumeFromFallback = (
		identifier: string,
		ttlSeconds: number,
	): boolean => {
		const now = Date.now();
		for (const [key, expiresAt] of fallback) {
			if (expiresAt <= now) {
				fallback.delete(key);
			}
		}

		const existing = fallback.get(identifier);
		if (existing && existing > now) {
			return false;
		}

		fallback.set(identifier, now + ttlSeconds * 1000);
		return true;
	};

	return {
		async consume(key: string, ttlSeconds: number): Promise<boolean> {
			return consumeFromFallback(`${NONCE_KEY_PREFIX}${key}`, ttlSeconds);
		},
	};
}

export function createAdapterNonceStore(
	adapter: VerificationAdapter,
): NonceStore {
	const fallback = new Map<string, number>();

	const consumeFromFallback = (
		identifier: string,
		ttlSeconds: number,
	): boolean => {
		const now = Date.now();
		for (const [key, expiresAt] of fallback) {
			if (expiresAt <= now) {
				fallback.delete(key);
			}
		}

		const existing = fallback.get(identifier);
		if (existing && existing > now) {
			return false;
		}

		fallback.set(identifier, now + ttlSeconds * 1000);
		return true;
	};

	return {
		async consume(key: string, ttlSeconds: number): Promise<boolean> {
			const identifier = `erc8128:nonce:${key}`;

			try {
				const existing = await adapter.findVerificationValue(identifier);
				if (existing) {
					return false;
				}

				await adapter.createVerificationValue({
					identifier,
					value: "1",
					expiresAt: new Date(Date.now() + ttlSeconds * 1000),
				});

				return true;
			} catch {
				return consumeFromFallback(identifier, ttlSeconds);
			}
		},
	};
}
