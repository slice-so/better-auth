import type { SecondaryStorage } from "@better-auth/core/db";

export type CacheValue = {
	address: string;
	chainId: number;
	keyId: string;
	expires: number;
	created: number;
};

export const DEFAULT_CACHE_SIZE = 10_000;
const CACHE_SWEEP_INTERVAL_MS = 60_000;
const CACHE_KEY_PREFIX = "erc8128:cache:";

/**
 * Unified interface for the replayable signature verification cache.
 *
 * This cache stores the result of successful replayable signature verifications
 * so that subsequent requests carrying the same signature can skip the expensive
 * cryptographic re-verification. It is a pure performance optimization — a cache
 * miss simply triggers a full verification; there is no security impact.
 *
 * This is separate from (and should not be confused with):
 * - **Nonce store** — replay protection for non-replayable signatures; stored in
 *   the `verification` table via `nonce-store.ts`. Security-critical.
 * - **Signature invalidation** — stored in the `erc8128Invalidation` table.
 *   Security-critical (losing state would re-enable revoked signatures).
 */
export interface VerificationCacheOps {
	get(sig: string): Promise<CacheValue | null>;
	set(sig: string, value: CacheValue, ttlSec: number): Promise<void>;
	delete(sig: string): Promise<void>;
	/** Evict entries matching keyId with created <= notBefore. No-op for external stores. */
	evictByKeyId(keyId: string, notBefore: number): void;
	/** Sweep expired entries from the in-memory tier. No-op for TTL-based stores. */
	sweep(): void;
}

/** Subset of `internalAdapter` used by the DB cache strategy. */
export interface VerificationCacheAdapter {
	findVerificationValue(
		identifier: string,
	): Promise<{ value: string; expiresAt: Date } | null>;
	createVerificationValue(data: {
		identifier: string;
		value: string;
		expiresAt: Date;
	}): Promise<unknown>;
	deleteVerificationByIdentifier(identifier: string): Promise<void>;
}

/**
 * Create cache ops for the resolved strategy.
 *
 * Strategy resolution:
 *   secondaryStorage available → use it (fastest, shared, TTL-managed)
 *   otherwise                  → DB via verification table + in-memory L1
 *
 * All implementations are resilient: cache failures are swallowed so they never
 * block request processing.
 */
export function createVerificationCacheOps(
	strategy: "secondary-storage" | "database" | "memory",
	secondaryStorage: SecondaryStorage | undefined,
	adapter: VerificationCacheAdapter,
	fallbackMap: Map<string, CacheValue>,
	maxSize: number,
): VerificationCacheOps {
	// --- Strategy: secondaryStorage (e.g. Redis) ---
	// Entries are stored with a TTL matching the signature's remaining validity.
	// evictByKeyId and sweep are no-ops: TTL handles expiry, and the per-request
	// DB invalidation check catches revoked signatures before using cached results.
	if (strategy === "secondary-storage" && secondaryStorage) {
		return {
			async get(sig) {
				try {
					const raw = await secondaryStorage.get(CACHE_KEY_PREFIX + sig);
					if (!raw) return null;
					return JSON.parse(raw as string) as CacheValue;
				} catch {
					return null;
				}
			},
			async set(sig, value, ttlSec) {
				try {
					await secondaryStorage.set(
						CACHE_KEY_PREFIX + sig,
						JSON.stringify(value),
						ttlSec,
					);
				} catch {}
			},
			async delete(sig) {
				try {
					await secondaryStorage.delete(CACHE_KEY_PREFIX + sig);
				} catch {}
			},
			evictByKeyId() {},
			sweep() {},
		};
	}

	// --- Shared: bounded in-memory Map helpers (used by both DB and memory strategies) ---
	const setInMemory = (sig: string, value: CacheValue) => {
		if (fallbackMap.has(sig)) fallbackMap.delete(sig);
		fallbackMap.set(sig, value);
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
		for (const [sig, value] of fallbackMap) {
			if (value.expires < nowSec) fallbackMap.delete(sig);
		}
	};

	const evictByKeyIdInMemory = (keyId: string, notBefore: number) => {
		for (const [sig, value] of fallbackMap) {
			if (value.keyId.toLowerCase() === keyId && value.created <= notBefore) {
				fallbackMap.delete(sig);
			}
		}
	};

	// --- Strategy: pure in-memory ---
	if (strategy === "memory") {
		return {
			async get(sig) {
				return fallbackMap.get(sig) ?? null;
			},
			async set(sig, value) {
				setInMemory(sig, value);
			},
			async delete(sig) {
				fallbackMap.delete(sig);
			},
			evictByKeyId: evictByKeyIdInMemory,
			sweep: sweepInMemory,
		};
	}

	// --- Strategy: DB (verification table) with in-memory read-through cache ---
	// Reads check the in-memory Map first (fast L1), then fall back to a DB query.
	// Writes persist to both in-memory and DB. DB entries expire via `expiresAt`.
	// If DB operations fail, the in-memory Map acts as a graceful fallback.
	return {
		async get(sig) {
			const inMemory = fallbackMap.get(sig);
			if (inMemory) return inMemory;
			try {
				const record = await adapter.findVerificationValue(
					CACHE_KEY_PREFIX + sig,
				);
				if (!record) return null;
				const parsed = JSON.parse(record.value) as CacheValue;
				setInMemory(sig, parsed);
				return parsed;
			} catch {
				return null;
			}
		},
		async set(sig, value, ttlSec) {
			setInMemory(sig, value);
			try {
				try {
					await adapter.deleteVerificationByIdentifier(CACHE_KEY_PREFIX + sig);
				} catch {}
				await adapter.createVerificationValue({
					identifier: CACHE_KEY_PREFIX + sig,
					value: JSON.stringify(value),
					expiresAt: new Date(Date.now() + ttlSec * 1000),
				});
			} catch {}
		},
		async delete(sig) {
			fallbackMap.delete(sig);
			try {
				await adapter.deleteVerificationByIdentifier(CACHE_KEY_PREFIX + sig);
			} catch {}
		},
		evictByKeyId: evictByKeyIdInMemory,
		sweep: sweepInMemory,
	};
}
