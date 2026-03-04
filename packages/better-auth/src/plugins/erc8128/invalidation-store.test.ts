import { describe, expect, it, vi } from "vitest";
import type { InvalidationAdapter } from "./invalidation-store";
import {
	createDBInvalidationOps,
	createDualInvalidationOps,
	createSecondaryStorageInvalidationOps,
} from "./invalidation-store";

// ---------------------------------------------------------------------------
// Mock DB adapter
// ---------------------------------------------------------------------------

function createMockAdapter() {
	const rows: Array<Record<string, unknown>> = [];
	let nextId = 1;

	const adapter: InvalidationAdapter = {
		async findMany(args) {
			if (!args.where) return [...rows];
			return rows.filter((r) =>
				args.where!.every(
					(w) => String(r[w.field] ?? "") === String(w.value ?? ""),
				),
			);
		},
		async findOne(args) {
			return (
				rows.find((r) =>
					args.where.every(
						(w) => String(r[w.field] ?? "") === String(w.value ?? ""),
					),
				) ?? null
			);
		},
		async create(args) {
			const row = { id: String(nextId++), ...args.data };
			rows.push(row);
			return row;
		},
		async update(args) {
			const row = rows.find((r) =>
				args.where.every(
					(w) => String(r[w.field] ?? "") === String(w.value ?? ""),
				),
			);
			if (row) Object.assign(row, args.update);
			return (row as Record<string, unknown>) ?? null;
		},
	};

	return { rows, adapter };
}

// ---------------------------------------------------------------------------
// Mock secondary storage
// ---------------------------------------------------------------------------
function createMockStorage() {
	const store = new Map<string, { value: string; expiresAt: number }>();
	return {
		store,
		storage: {
			async get(key: string) {
				const entry = store.get(key);
				if (!entry) return null;
				if (entry.expiresAt <= Date.now()) {
					store.delete(key);
					return null;
				}
				return entry.value;
			},
			async set(key: string, value: string, ttl?: number) {
				store.set(key, {
					value,
					expiresAt: Date.now() + (ttl ?? 3600) * 1000,
				});
			},
			async delete(key: string) {
				store.delete(key);
			},
		},
	};
}

describe("DB invalidation ops", () => {
	it("upserts and finds per-keyId notBefore", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);

		await ops.upsertKeyIdNotBefore("erc8128:1:0xabc", 1000);
		const records = await ops.findByKeyId("erc8128:1:0xabc");
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(1000);
	});

	it("updates existing per-keyId notBefore on second upsert", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);

		await ops.upsertKeyIdNotBefore("erc8128:1:0xabc", 1000);
		await ops.upsertKeyIdNotBefore("erc8128:1:0xabc", 2000);
		const records = await ops.findByKeyId("erc8128:1:0xabc");
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(2000);
	});

	it("upserts and finds per-signature invalidation", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);

		await ops.upsertSignatureInvalidation("erc8128:1:0xabc", "0xsig1", 300);
		const record = await ops.findBySignature("0xsig1");
		expect(record).not.toBeNull();
		expect(record?.notBefore).toBe(0);
	});

	it("returns null for non-existent signature", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);
		expect(await ops.findBySignature("0xmissing")).toBeNull();
	});

	it("normalizes keyId to lowercase", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);

		await ops.upsertKeyIdNotBefore("ERC8128:1:0xABC", 1000);
		const records = await ops.findByKeyId("erc8128:1:0xABC");
		expect(records).toHaveLength(1);
	});
});

describe("secondaryStorage invalidation ops", () => {
	it("stores and retrieves per-keyId notBefore", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);

		await ops.upsertKeyIdNotBefore("erc8128:1:0xabc", 1500);
		const records = await ops.findByKeyId("erc8128:1:0xabc");
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(1500);
	});

	it("overwrites per-keyId notBefore on second upsert", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);

		await ops.upsertKeyIdNotBefore("erc8128:1:0xabc", 1000);
		await ops.upsertKeyIdNotBefore("erc8128:1:0xabc", 2000);
		const records = await ops.findByKeyId("erc8128:1:0xabc");
		expect(records[0]!.notBefore).toBe(2000);
	});

	it("stores and retrieves per-signature invalidation", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);

		await ops.upsertSignatureInvalidation("erc8128:1:0xabc", "0xsig1", 300);
		const record = await ops.findBySignature("0xsig1");
		expect(record).not.toBeNull();
	});

	it("returns empty array for missing keyId", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);
		expect(await ops.findByKeyId("missing")).toEqual([]);
	});

	it("returns null for missing signature", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);
		expect(await ops.findBySignature("0xmissing")).toBeNull();
	});

	it("swallows errors gracefully", async () => {
		const storage = {
			async get() {
				throw new Error("Redis down");
			},
			async set() {
				throw new Error("Redis down");
			},
			async delete() {
				throw new Error("Redis down");
			},
		};
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);

		// Should not throw
		await ops.upsertKeyIdNotBefore("key", 1000);
		await ops.upsertSignatureInvalidation("key", "0xsig", 300);
		expect(await ops.findByKeyId("key")).toEqual([]);
		expect(await ops.findBySignature("0xsig")).toBeNull();
	});

	it("respects TTL expiry", async () => {
		vi.useFakeTimers();
		try {
			const { storage } = createMockStorage();
			const ops = createSecondaryStorageInvalidationOps(storage, 1);

			await ops.upsertKeyIdNotBefore("erc8128:1:0xabc", 1000, 1);
			expect(await ops.findByKeyId("erc8128:1:0xabc")).toHaveLength(1);

			vi.advanceTimersByTime(1100);
			expect(await ops.findByKeyId("erc8128:1:0xabc")).toEqual([]);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("dual invalidation ops", () => {
	it("writes to both DB and secondaryStorage", async () => {
		const { adapter } = createMockAdapter();
		const { storage } = createMockStorage();

		const dbOps = createDBInvalidationOps(adapter);
		const ssOps = createSecondaryStorageInvalidationOps(storage, 3600);
		const dualOps = createDualInvalidationOps(dbOps, ssOps);

		await dualOps.upsertKeyIdNotBefore("erc8128:1:0xabc", 1000);

		// Both should have the record
		expect(await dbOps.findByKeyId("erc8128:1:0xabc")).toHaveLength(1);
		expect(await ssOps.findByKeyId("erc8128:1:0xabc")).toHaveLength(1);
	});

	it("reads from secondaryStorage first, falls back to DB", async () => {
		const { adapter } = createMockAdapter();
		const { storage } = createMockStorage();

		const dbOps = createDBInvalidationOps(adapter);
		const ssOps = createSecondaryStorageInvalidationOps(storage, 3600);
		const dualOps = createDualInvalidationOps(dbOps, ssOps);

		// Write only to DB
		await dbOps.upsertKeyIdNotBefore("erc8128:1:0xdb-only", 500);

		// Dual should find it via DB fallback
		const records = await dualOps.findByKeyId("erc8128:1:0xdb-only");
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(500);
	});

	it("prefers secondaryStorage over DB on read", async () => {
		const { adapter } = createMockAdapter();
		const { storage } = createMockStorage();

		const dbOps = createDBInvalidationOps(adapter);
		const ssOps = createSecondaryStorageInvalidationOps(storage, 3600);
		const dualOps = createDualInvalidationOps(dbOps, ssOps);

		// Write different values to each
		await dbOps.upsertKeyIdNotBefore("erc8128:1:0xabc", 100);
		await ssOps.upsertKeyIdNotBefore("erc8128:1:0xabc", 200);

		const records = await dualOps.findByKeyId("erc8128:1:0xabc");
		expect(records[0]!.notBefore).toBe(200); // SS wins
	});

	it("dual-writes signature invalidation", async () => {
		const { adapter } = createMockAdapter();
		const { storage } = createMockStorage();

		const dbOps = createDBInvalidationOps(adapter);
		const ssOps = createSecondaryStorageInvalidationOps(storage, 3600);
		const dualOps = createDualInvalidationOps(dbOps, ssOps);

		await dualOps.upsertSignatureInvalidation("erc8128:1:0xabc", "0xsig", 300);

		expect(await dbOps.findBySignature("0xsig")).not.toBeNull();
		expect(await ssOps.findBySignature("0xsig")).not.toBeNull();
	});
});
