import type { SecondaryStorage } from "@better-auth/core/db";
import type { Where } from "@better-auth/core/db/adapter";
import {
	getErc8128InvalidationMatchKey,
	getErc8128SignatureHash,
	getErc8128SignatureInvalidationMatchKey,
	parseErc8128KeyId,
} from "./utils";

/** Minimum TTL floor for invalidation records (30 days). */
export const DEFAULT_INVALIDATION_TTL_SEC = 30 * 24 * 60 * 60;
const INV_KEY_PREFIX = "erc8128:inv:key:";
const INV_SIG_PREFIX = "erc8128:inv:sig:";

export interface InvalidationRecord {
	keyId?: string;
	signatureHash?: string;
	notBefore: number;
}

/**
 * Abstraction over invalidation storage. Implementations back either the
 * database (`erc8128Invalidation` table) or `secondaryStorage` (Redis).
 */
export interface InvalidationOps {
	findByKeyId(keyId: string): Promise<InvalidationRecord[]>;
	findBySignature(
		signature: string,
		keyId?: string | null,
	): Promise<InvalidationRecord | null>;
	upsertKeyIdNotBefore(
		keyId: string,
		notBefore: number,
		ttlSec?: number,
	): Promise<void>;
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
	deleteMany(args: {
		model: string;
		where: Where[];
	}): Promise<number>;
}

function toInvalidationRecord(
	row: Record<string, unknown>,
): InvalidationRecord | null {
	if (typeof row.address !== "string" || typeof row.chainId !== "number") {
		return null;
	}
	return {
		keyId: `erc8128:${row.chainId}:${row.address.toLowerCase()}`,
		signatureHash:
			typeof row.signatureHash === "string" ? row.signatureHash : undefined,
		notBefore: typeof row.notBefore === "number" ? row.notBefore : 0,
	};
}

function isExpired(record: Record<string, unknown>) {
	if (!(record.expiresAt instanceof Date)) {
		if (!record.expiresAt) {
			return false;
		}
		return new Date(record.expiresAt as string | number | Date).getTime() <= Date.now();
	}
	return record.expiresAt.getTime() <= Date.now();
}

export function createDBInvalidationOps(
	adapter: InvalidationAdapter,
): InvalidationOps {
	return {
		async findByKeyId(keyId: string): Promise<InvalidationRecord[]> {
			const matchKey = getErc8128InvalidationMatchKey(keyId);
			if (!matchKey) {
				return [];
			}
			const row = await adapter.findOne({
				model: "erc8128Invalidation",
				where: [
					{ field: "kind", operator: "eq", value: "key" },
					{ field: "matchKey", operator: "eq", value: matchKey },
				],
			});
			const record =
				row && !isExpired(row) ? toInvalidationRecord(row) : null;
			return record ? [record] : [];
		},

		async findBySignature(
			signature: string,
			keyId?: string | null,
		): Promise<InvalidationRecord | null> {
			const signatureHash = getErc8128SignatureHash(signature);
			const exactMatchKey =
				keyId && getErc8128SignatureInvalidationMatchKey(keyId, signatureHash);
			const where: Where[] = exactMatchKey
				? [
						{ field: "kind", operator: "eq", value: "signature" },
						{ field: "matchKey", operator: "eq", value: exactMatchKey },
					]
				: [
						{ field: "kind", operator: "eq", value: "signature" },
						{ field: "signatureHash", operator: "eq", value: signatureHash },
					];
			const rows = exactMatchKey
				? await adapter
						.findOne({
							model: "erc8128Invalidation",
							where,
						})
						.then((row) => (row ? [row] : []))
				: await adapter.findMany({
						model: "erc8128Invalidation",
						where,
					});
			const validRows = rows.filter((row) => !isExpired(row));
			if (!validRows.length) {
				return null;
			}
			return toInvalidationRecord(validRows[0]!);
		},

		async upsertKeyIdNotBefore(
			keyId: string,
			notBefore: number,
			ttlSec?: number,
		) {
			const parsed = parseErc8128KeyId(keyId);
			const matchKey = getErc8128InvalidationMatchKey(keyId);
			if (!parsed || !matchKey) {
				return;
			}
			const expirationWindowSec = ttlSec ?? DEFAULT_INVALIDATION_TTL_SEC;
			const expiresAt = new Date((notBefore + expirationWindowSec) * 1000);
			const existing = await adapter.findOne({
				model: "erc8128Invalidation",
				where: [
					{ field: "kind", operator: "eq", value: "key" },
					{ field: "matchKey", operator: "eq", value: matchKey },
				],
			});
			if (existing) {
				await adapter.update({
					model: "erc8128Invalidation",
					where: [{ field: "id", operator: "eq", value: String(existing.id) }],
					update: { notBefore, expiresAt },
				});
				return;
			}
			await adapter.create({
				model: "erc8128Invalidation",
				data: {
					kind: "key",
					matchKey,
					address: parsed.address.toLowerCase(),
					chainId: parsed.chainId,
					notBefore,
					expiresAt,
				},
			});
		},

		async upsertSignatureInvalidation(
			keyId: string,
			signature: string,
			ttlSec: number,
		) {
			const parsed = parseErc8128KeyId(keyId);
			const signatureHash = getErc8128SignatureHash(signature);
			const matchKey = getErc8128SignatureInvalidationMatchKey(
				keyId,
				signatureHash,
			);
			if (!parsed || !matchKey) {
				return;
			}
			const expiresAt = new Date(Date.now() + ttlSec * 1000);
			const existing = await adapter.findOne({
				model: "erc8128Invalidation",
				where: [
					{ field: "kind", operator: "eq", value: "signature" },
					{ field: "matchKey", operator: "eq", value: matchKey },
				],
			});
			if (existing) {
				await adapter.update({
					model: "erc8128Invalidation",
					where: [{ field: "id", operator: "eq", value: String(existing.id) }],
					update: { expiresAt },
				});
				return;
			}
			await adapter.create({
				model: "erc8128Invalidation",
				data: {
					kind: "signature",
					matchKey,
					address: parsed.address.toLowerCase(),
					chainId: parsed.chainId,
					signatureHash,
					expiresAt,
				},
			});
		},
	};
}

/**
 * Invalidation ops backed by `secondaryStorage` (e.g. Redis).
 *
 * Storage layout:
 * - `erc8128:inv:key:<matchKey>` -> JSON `{ keyId, notBefore }`
 * - `erc8128:inv:sig:<matchKey>:<signatureHash>` -> JSON `{ keyId, signatureHash, notBefore }`
 */
export function createSecondaryStorageInvalidationOps(
	storage: SecondaryStorage,
	defaultTtlSec: number = DEFAULT_INVALIDATION_TTL_SEC,
): InvalidationOps {
	return {
		async findByKeyId(keyId: string): Promise<InvalidationRecord[]> {
			const matchKey = getErc8128InvalidationMatchKey(keyId);
			if (!matchKey) {
				return [];
			}
			try {
				const raw = await storage.get(`${INV_KEY_PREFIX}${matchKey}`);
				if (!raw) return [];
				return [JSON.parse(raw as string) as InvalidationRecord];
			} catch {
				return [];
			}
		},

		async findBySignature(
			signature: string,
			keyId?: string | null,
		): Promise<InvalidationRecord | null> {
			const signatureHash = getErc8128SignatureHash(signature);
			const matchKey =
				keyId &&
				getErc8128SignatureInvalidationMatchKey(keyId, signatureHash);
			if (!matchKey) {
				return null;
			}
			try {
				const raw = await storage.get(`${INV_SIG_PREFIX}${matchKey}`);
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
			const matchKey = getErc8128InvalidationMatchKey(keyId);
			if (!matchKey) {
				return;
			}
			try {
				const expirationWindowSec = ttlSec ?? defaultTtlSec;
				const ttlUntilExpiry = Math.max(
					notBefore + expirationWindowSec - Math.floor(Date.now() / 1000),
					1,
				);
				await storage.set(
					`${INV_KEY_PREFIX}${matchKey}`,
					JSON.stringify({
						keyId: matchKey,
						notBefore,
					} satisfies InvalidationRecord),
					ttlUntilExpiry,
				);
			} catch {}
		},

		async upsertSignatureInvalidation(
			keyId: string,
			signature: string,
			ttlSec: number,
		) {
			const signatureHash = getErc8128SignatureHash(signature);
			const matchKey = getErc8128SignatureInvalidationMatchKey(
				keyId,
				signatureHash,
			);
			if (!matchKey) {
				return;
			}
			try {
				await storage.set(
					`${INV_SIG_PREFIX}${matchKey}`,
					JSON.stringify({
						keyId: getErc8128InvalidationMatchKey(keyId) ?? undefined,
						signatureHash,
						notBefore: 0,
					} satisfies InvalidationRecord),
					ttlSec,
				);
			} catch {}
		},
	};
}

export function createMemoryInvalidationOps(
	defaultTtlSec: number = DEFAULT_INVALIDATION_TTL_SEC,
): InvalidationOps {
	const keyIdStore = new Map<
		string,
		{ record: InvalidationRecord; expiresAt: number }
	>();
	const sigStore = new Map<
		string,
		{ record: InvalidationRecord; expiresAt: number }
	>();

	const sweep = () => {
		const nowSec = Math.floor(Date.now() / 1000);
		for (const [k, v] of keyIdStore) {
			if (v.expiresAt <= nowSec) keyIdStore.delete(k);
		}
		for (const [k, v] of sigStore) {
			if (v.expiresAt <= nowSec) sigStore.delete(k);
		}
	};

	return {
		async findByKeyId(keyId: string): Promise<InvalidationRecord[]> {
			sweep();
			const matchKey = getErc8128InvalidationMatchKey(keyId);
			if (!matchKey) {
				return [];
			}
			const row = keyIdStore.get(matchKey);
			return row ? [row.record] : [];
		},

		async findBySignature(
			signature: string,
			keyId?: string | null,
		): Promise<InvalidationRecord | null> {
			sweep();
			const signatureHash = getErc8128SignatureHash(signature);
			const matchKey =
				keyId &&
				getErc8128SignatureInvalidationMatchKey(keyId, signatureHash);
			if (!matchKey) {
				return null;
			}
			return sigStore.get(matchKey)?.record ?? null;
		},

		async upsertKeyIdNotBefore(
			keyId: string,
			notBefore: number,
			ttlSec?: number,
		): Promise<void> {
			sweep();
			const matchKey = getErc8128InvalidationMatchKey(keyId);
			if (!matchKey) {
				return;
			}
			keyIdStore.set(matchKey, {
				record: {
					keyId: matchKey,
					notBefore,
				},
				expiresAt: notBefore + (ttlSec ?? defaultTtlSec),
			});
		},

		async upsertSignatureInvalidation(
			keyId: string,
			signature: string,
			ttlSec: number,
		): Promise<void> {
			sweep();
			const signatureHash = getErc8128SignatureHash(signature);
			const matchKey = getErc8128SignatureInvalidationMatchKey(
				keyId,
				signatureHash,
			);
			if (!matchKey) {
				return;
			}
			sigStore.set(matchKey, {
				record: {
					keyId: getErc8128InvalidationMatchKey(keyId) ?? undefined,
					signatureHash,
					notBefore: 0,
				},
				expiresAt: Math.floor(Date.now() / 1000) + ttlSec,
			});
		},
	};
}

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
			keyId?: string | null,
		): Promise<InvalidationRecord | null> {
			const ssResult = await ss.findBySignature(signature, keyId);
			if (ssResult) return ssResult;
			return db.findBySignature(signature, keyId);
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
