import type { SecondaryStorage } from "@better-auth/core/db";
import type { Where } from "@better-auth/core/db/adapter";

/** Minimum TTL floor for invalidation records (30 days). */
export const DEFAULT_INVALIDATION_TTL_SEC = 30 * 24 * 60 * 60;
const INV_KEY_PREFIX = "erc8128:inv:keyid:";
const INV_SIG_PREFIX = "erc8128:inv:sig:";

export interface InvalidationRecord {
	keyId?: string;
	signature?: string;
	notBefore: number;
}

/**
 * Abstraction over invalidation storage. Implementations back either the
 * database (`erc8128Invalidation` table) or `secondaryStorage` (Redis).
 */
export interface InvalidationOps {
	/** Find all invalidation records for a keyId (per-keyId notBefore + per-signature). */
	findByKeyId(keyId: string): Promise<InvalidationRecord[]>;
	/** Find a per-signature invalidation record. */
	findBySignature(signature: string): Promise<InvalidationRecord | null>;
	/** Upsert a per-keyId notBefore invalidation record. */
	upsertKeyIdNotBefore(
		keyId: string,
		notBefore: number,
		ttlSec?: number,
	): Promise<void>;
	/** Create or update a per-signature invalidation record. */
	upsertSignatureInvalidation(
		keyId: string,
		signature: string,
		ttlSec: number,
	): Promise<void>;
}

/** Minimal adapter surface used by the invalidation store. */
export interface InvalidationAdapter {
	findMany(args: {
		model: string;
		where?: Where[];
	}): Promise<Record<string, unknown>[]>;
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
}

function toInvalidationRecord(
	row: Record<string, unknown>,
): InvalidationRecord {
	return {
		keyId: typeof row.keyId === "string" ? row.keyId : undefined,
		signature: typeof row.signature === "string" ? row.signature : undefined,
		notBefore: typeof row.notBefore === "number" ? row.notBefore : 0,
	};
}

// ---------------------------------------------------------------------------
// Database-backed implementation (current behavior)
// ---------------------------------------------------------------------------

export function createDBInvalidationOps(
	adapter: InvalidationAdapter,
): InvalidationOps {
	return {
		async findByKeyId(keyId: string): Promise<InvalidationRecord[]> {
			const rows = await adapter.findMany({
				model: "erc8128Invalidation",
				where: [{ field: "keyId", operator: "eq", value: keyId.toLowerCase() }],
			});
			return rows.map(toInvalidationRecord);
		},

		async findBySignature(
			signature: string,
		): Promise<InvalidationRecord | null> {
			const row = await adapter.findOne({
				model: "erc8128Invalidation",
				where: [{ field: "signature", operator: "eq", value: signature }],
			});
			return row ? toInvalidationRecord(row) : null;
		},

		async upsertKeyIdNotBefore(keyId: string, notBefore: number) {
			const normalizedKeyId = keyId.toLowerCase();
			const records = await adapter.findMany({
				model: "erc8128Invalidation",
				where: [{ field: "keyId", operator: "eq", value: normalizedKeyId }],
			});
			const existing = records.find((r) => !r.signature);

			if (!existing) {
				await adapter.create({
					model: "erc8128Invalidation",
					data: {
						keyId: normalizedKeyId,
						notBefore,
						updatedAt: new Date(),
					},
				});
			} else {
				await adapter.update({
					model: "erc8128Invalidation",
					where: [{ field: "id", operator: "eq", value: String(existing.id) }],
					update: { notBefore, updatedAt: new Date() },
				});
			}
		},

		async upsertSignatureInvalidation(
			keyId: string,
			signature: string,
			ttlSec: number,
		) {
			const expiresAt = Math.floor(Date.now() / 1000) + ttlSec;
			const existing = await adapter.findOne({
				model: "erc8128Invalidation",
				where: [{ field: "signature", operator: "eq", value: signature }],
			});

			if (!existing) {
				await adapter.create({
					model: "erc8128Invalidation",
					data: {
						signature,
						keyId: keyId.toLowerCase(),
						notBefore: 0,
						expiresAt,
						updatedAt: new Date(),
					},
				});
			} else {
				await adapter.update({
					model: "erc8128Invalidation",
					where: [{ field: "id", operator: "eq", value: String(existing.id) }],
					update: { expiresAt },
				});
			}
		},
	};
}

// ---------------------------------------------------------------------------
// SecondaryStorage-backed implementation (Redis)
// ---------------------------------------------------------------------------

/**
 * Invalidation ops backed by `secondaryStorage` (e.g. Redis).
 *
 * Storage layout:
 * - `erc8128:inv:keyid:<keyId>` → JSON `{ notBefore }` with TTL
 * - `erc8128:inv:sig:<signature>` → JSON `{ keyId, notBefore: 0 }` with TTL
 *
 * `findByKeyId` returns up to 1 record (the per-keyId notBefore). Per-signature
 * lookups are separate keys, looked up individually via `findBySignature`.
 * This means the middleware issues two parallel `get` calls instead of one DB
 * `findMany` with OR — same number of round-trips in practice, faster on Redis.
 */
export function createSecondaryStorageInvalidationOps(
	storage: SecondaryStorage,
	defaultTtlSec: number = DEFAULT_INVALIDATION_TTL_SEC,
): InvalidationOps {
	return {
		async findByKeyId(keyId: string): Promise<InvalidationRecord[]> {
			try {
				const raw = await storage.get(
					`${INV_KEY_PREFIX}${keyId.toLowerCase()}`,
				);
				if (!raw) return [];
				const parsed = JSON.parse(raw as string) as { notBefore: number };
				return [{ notBefore: parsed.notBefore }];
			} catch {
				return [];
			}
		},

		async findBySignature(
			signature: string,
		): Promise<InvalidationRecord | null> {
			try {
				const raw = await storage.get(`${INV_SIG_PREFIX}${signature}`);
				if (!raw) return null;
				return JSON.parse(raw as string) as InvalidationRecord;
			} catch {
				return null;
			}
		},

		async upsertKeyIdNotBefore(
			keyId: string,
			notBefore: number,
			ttlSec?: number,
		) {
			try {
				await storage.set(
					`${INV_KEY_PREFIX}${keyId.toLowerCase()}`,
					JSON.stringify({ notBefore }),
					ttlSec ?? defaultTtlSec,
				);
			} catch {}
		},

		async upsertSignatureInvalidation(
			keyId: string,
			signature: string,
			ttlSec: number,
		) {
			try {
				await storage.set(
					`${INV_SIG_PREFIX}${signature}`,
					JSON.stringify({
						keyId: keyId.toLowerCase(),
						notBefore: 0,
						signature,
					}),
					ttlSec,
				);
			} catch {}
		},
	};
}

// ---------------------------------------------------------------------------
// Dual-write implementation (DB + secondaryStorage)
// ---------------------------------------------------------------------------

/**
 * Writes to both DB and secondaryStorage; reads from secondaryStorage first,
 * falls back to DB on miss. Used when `storeInDatabase: true` is set with
 * `secondaryStorage` configured.
 */
export function createDualInvalidationOps(
	db: InvalidationOps,
	ss: InvalidationOps,
): InvalidationOps {
	return {
		async findByKeyId(keyId: string): Promise<InvalidationRecord[]> {
			const ssResult = await ss.findByKeyId(keyId);
			if (ssResult.length > 0) return ssResult;
			return db.findByKeyId(keyId);
		},

		async findBySignature(
			signature: string,
		): Promise<InvalidationRecord | null> {
			const ssResult = await ss.findBySignature(signature);
			if (ssResult) return ssResult;
			return db.findBySignature(signature);
		},

		async upsertKeyIdNotBefore(
			keyId: string,
			notBefore: number,
			ttlSec?: number,
		) {
			await Promise.all([
				db.upsertKeyIdNotBefore(keyId, notBefore),
				ss.upsertKeyIdNotBefore(keyId, notBefore, ttlSec),
			]);
		},

		async upsertSignatureInvalidation(
			keyId: string,
			signature: string,
			ttlSec: number,
		) {
			await Promise.all([
				db.upsertSignatureInvalidation(keyId, signature, ttlSec),
				ss.upsertSignatureInvalidation(keyId, signature, ttlSec),
			]);
		},
	};
}
