import type { SecondaryStorage } from "@better-auth/core/db";
import type { Where } from "@better-auth/core/db/adapter";
import type { NonceStore } from "@slicekit/erc8128";

interface NonceAdapter {
	findOne(args: {
		model: string;
		where: Where[];
	}): Promise<Record<string, unknown> | null>;
	create(args: {
		model: string;
		data: Record<string, unknown>;
	}): Promise<Record<string, unknown>>;
	deleteMany(args: {
		model: string;
		where: Where[];
	}): Promise<number>;
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
 * Dual-write NonceStore: consumes from both `erc8128Nonce` and secondaryStorage.
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

export function createAdapterNonceStore(adapter: NonceAdapter): NonceStore {
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
			const nonceKey = key;

			try {
				const existing = await adapter.findOne({
					model: "erc8128Nonce",
					where: [{ field: "nonceKey", operator: "eq", value: nonceKey }],
				});
				const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
				const existingExpiresAt = existing?.expiresAt
					? new Date(existing.expiresAt as string | number | Date)
					: null;
				if (
					existing &&
					existingExpiresAt &&
					existingExpiresAt.getTime() > Date.now()
				) {
					return false;
				}
				if (existing) {
					await adapter.deleteMany({
						model: "erc8128Nonce",
						where: [
							{ field: "id", operator: "eq", value: String(existing.id) },
						],
					});
				}
				await adapter.create({
					model: "erc8128Nonce",
					data: {
						nonceKey,
						expiresAt,
					},
				});

				return true;
			} catch {
				return consumeFromFallback(
					`${NONCE_KEY_PREFIX}${nonceKey}`,
					ttlSeconds,
				);
			}
		},
	};
}
