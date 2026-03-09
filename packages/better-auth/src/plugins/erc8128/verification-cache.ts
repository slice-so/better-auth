import type { SecondaryStorage } from "@better-auth/core/db";
import type { Where } from "@better-auth/core/db/adapter";

export type CacheValue = {
	verified: true;
	expires: number;
};

export const DEFAULT_CACHE_SIZE = 10_000;
const CACHE_SWEEP_INTERVAL_MS = 60_000;
const CACHE_KEY_PREFIX = "erc8128:cache:";

/**
 * Unified interface for the replayable signature verification cache.
 *
 * This cache stores successful `verifyMessage` outcomes so replayable signatures
 * can skip repeated EOA recovery / ERC-1271 `isValidSignature` checks. Request
 * verification still runs fully on every request; this cache only avoids the
 * expensive cryptographic sub-step. It is a pure performance optimization.
 *
 * This is separate from (and should not be confused with):
 * - **Nonce store** — replay protection for non-replayable signatures; stored in
 *   the `erc8128Nonce` table via `nonce-store.ts`. Security-critical.
 * - **Signature invalidation** — stored in the `erc8128Invalidation` table.
 *   Security-critical (losing state would re-enable revoked signatures).
 */
export interface VerificationCacheOps {
	get(key: string): Promise<CacheValue | null>;
	set(data: {
		key: string;
		value: CacheValue;
		ttlSec: number;
		address: string;
		chainId: number;
		signatureHash: string;
		expiresAt: Date;
	}): Promise<void>;
	delete(key: string): Promise<void>;
	/** Sweep expired entries from the in-memory tier. No-op for TTL-based stores. */
	sweep(): void;
}

export interface VerificationCacheAdapter {
	findOne(args: {
		model: string;
		where: Where[];
	}): Promise<Record<string, unknown> | null>;
	create(args: {
		model: string;
		data: Record<string, unknown>;
	}): Promise<Record<string, unknown>>;
	update(args: {
		model: string;
		where: Where[];
		update: Record<string, unknown>;
	}): Promise<unknown>;
	deleteMany(args: {
		model: string;
		where: Where[];
	}): Promise<number>;
}

/**
 * Create cache ops for the resolved strategy.
 *
 * Strategy resolution:
 *   secondaryStorage available → use it (fastest, shared, TTL-managed)
 *   otherwise                  → DB via `erc8128VerificationCache` + in-memory L1
 *
 * All implementations are resilient: cache failures are swallowed so they never
 * block request processing.
 */
export function createVerificationCacheOps(
	strategy: "secondary-storage" | "database",
	secondaryStorage: SecondaryStorage | undefined,
	adapter: VerificationCacheAdapter,
	fallbackMap: Map<string, CacheValue>,
	maxSize: number,
): VerificationCacheOps {
	// --- Strategy: secondaryStorage (e.g. Redis) ---
	// Entries are stored with a TTL matching the signature validity window.
	// sweep is a no-op because TTL handles expiry.
	if (strategy === "secondary-storage" && secondaryStorage) {
		return {
			async get(key) {
				try {
					const raw = await secondaryStorage.get(CACHE_KEY_PREFIX + key);
					if (!raw) return null;
					return JSON.parse(raw as string) as CacheValue;
				} catch {
					return null;
				}
			},
			async set({ key, value, ttlSec }) {
				try {
					await secondaryStorage.set(
						CACHE_KEY_PREFIX + key,
						JSON.stringify(value),
						ttlSec,
					);
				} catch {}
			},
			async delete(key) {
				try {
					await secondaryStorage.delete(CACHE_KEY_PREFIX + key);
				} catch {}
			},
			sweep() {},
		};
	}

	// --- Shared: bounded in-memory Map helpers ---
	const setInMemory = (key: string, value: CacheValue) => {
		if (fallbackMap.has(key)) fallbackMap.delete(key);
		fallbackMap.set(key, value);
		// LRU eviction: drop oldest entry when over capacity
		if (fallbackMap.size > maxSize) {
			const oldest = fallbackMap.keys().next().value;
			if (oldest) fallbackMap.delete(oldest);
		}
	};

	let lastSweepMs = 0;
	const sweepInMemory = () => {
		const nowMs = Date.now();
		if (nowMs - lastSweepMs < CACHE_SWEEP_INTERVAL_MS) return;
		lastSweepMs = nowMs;
		const nowSec = Math.floor(nowMs / 1000);
		for (const [key, value] of fallbackMap) {
			if (value.expires < nowSec) {
				fallbackMap.delete(key);
			}
		}
	};

	// --- Strategy: DB (`erc8128VerificationCache`) with in-memory read-through cache ---
	// Reads check the in-memory Map first (fast L1), then fall back to a DB query.
	// Writes persist to both in-memory and DB. DB entries expire via `expiresAt`.
	// If DB operations fail, the in-memory Map acts as a graceful fallback.
	return {
		async get(key) {
			const inMemory = fallbackMap.get(key);
			if (inMemory) return inMemory;
			try {
				const record = await adapter.findOne({
					model: "erc8128VerificationCache",
					where: [{ field: "cacheKey", operator: "eq", value: key }],
				});
				if (!record) return null;
				const expiresAt = new Date(record.expiresAt as string | number | Date);
				if (expiresAt.getTime() <= Date.now()) {
					return null;
				}
				const parsed = {
					verified: true,
					expires: Math.floor(expiresAt.getTime() / 1000),
				} satisfies CacheValue;
				setInMemory(key, parsed);
				return parsed;
			} catch {
				return null;
			}
		},
		async set(data) {
			const { key, value, address, chainId, signatureHash, expiresAt } = data;
			setInMemory(key, value);
			try {
				const existing = await adapter.findOne({
					model: "erc8128VerificationCache",
					where: [{ field: "cacheKey", operator: "eq", value: key }],
				});
				if (existing) {
					await adapter.update({
						model: "erc8128VerificationCache",
						where: [{ field: "id", operator: "eq", value: String(existing.id) }],
						update: {
							address,
							chainId,
							signatureHash,
							expiresAt,
						},
					});
				} else {
					await adapter.create({
						model: "erc8128VerificationCache",
						data: {
							cacheKey: key,
							address,
							chainId,
							signatureHash,
							expiresAt,
						},
					});
				}
			} catch {}
		},
		async delete(key) {
			fallbackMap.delete(key);
			try {
				await adapter.deleteMany({
					model: "erc8128VerificationCache",
					where: [{ field: "cacheKey", operator: "eq", value: key }],
				});
			} catch {}
		},
		sweep: sweepInMemory,
	};
}
