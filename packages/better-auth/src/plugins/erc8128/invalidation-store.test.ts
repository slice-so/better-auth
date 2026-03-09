import { describe, expect, it, vi } from "vitest";
import type { InvalidationAdapter } from "./invalidation-store";
import {
	createDBInvalidationOps,
	createDualInvalidationOps,
	createSecondaryStorageInvalidationOps,
} from "./invalidation-store";
import { getErc8128SignatureHash } from "./utils";

const KEY_ID_ABC = "erc8128:1:0x0000000000000000000000000000000000000abc";
const KEY_ID_DB_ONLY =
	"erc8128:1:0x0000000000000000000000000000000000000db0";

function createMockAdapter() {
	const rows: Array<Record<string, unknown>> = [];
	let nextId = 1;

	const adapter: InvalidationAdapter = {
		async findMany(args) {
			if (!args.where) return [...rows];
			return rows.filter((row) =>
				args.where!.every((where) => {
					if (where.field === "expiresAt" && where.operator === "lt") {
						return (
							row.expiresAt instanceof Date &&
							row.expiresAt < (where.value as Date)
						);
					}
					return String(row[where.field] ?? "") === String(where.value ?? "");
				}),
			);
		},
		async findOne(args) {
			return (
				rows.find((row) =>
					args.where.every(
						(where) =>
							String(row[where.field] ?? "") === String(where.value ?? ""),
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
			const row = rows.find((entry) =>
				args.where.every(
					(where) =>
						String(entry[where.field] ?? "") === String(where.value ?? ""),
				),
			);
			if (row) Object.assign(row, args.update);
			return row ?? null;
		},
		async deleteMany(args) {
			let deleted = 0;
			for (const row of [...rows]) {
				if (
					args.where.every((where) => {
						if (where.field === "expiresAt" && where.operator === "lt") {
							return (
								row.expiresAt instanceof Date &&
								row.expiresAt < (where.value as Date)
							);
						}
						return String(row[where.field] ?? "") === String(where.value ?? "");
					})
				) {
					rows.splice(rows.indexOf(row), 1);
					deleted++;
				}
			}
			return deleted;
		},
	};

	return { rows, adapter };
}

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
		const nowSec = Math.floor(Date.now() / 1000);

		await ops.upsertKeyIdNotBefore(KEY_ID_ABC, nowSec);
		const records = await ops.findByKeyId(KEY_ID_ABC);
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(nowSec);
		expect(records[0]!.keyId).toBe(KEY_ID_ABC);
	});

	it("updates existing per-keyId notBefore on second upsert", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);
		const nowSec = Math.floor(Date.now() / 1000);

		await ops.upsertKeyIdNotBefore(KEY_ID_ABC, nowSec);
		await ops.upsertKeyIdNotBefore(KEY_ID_ABC, nowSec + 1000);
		const records = await ops.findByKeyId(KEY_ID_ABC);
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(nowSec + 1000);
	});

	it("ignores expired per-keyId invalidations", async () => {
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date(1000 * 1000));
			const { adapter } = createMockAdapter();
			const ops = createDBInvalidationOps(adapter);

			await ops.upsertKeyIdNotBefore(KEY_ID_ABC, 1000, 1);
			expect(await ops.findByKeyId(KEY_ID_ABC)).toHaveLength(1);

			vi.setSystemTime(new Date((1000 + 2) * 1000));
			expect(await ops.findByKeyId(KEY_ID_ABC)).toEqual([]);
		} finally {
			vi.useRealTimers();
		}
	});

	it("upserts and finds per-signature invalidation", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);

		await ops.upsertSignatureInvalidation(KEY_ID_ABC, "0xsig1", 300);
		const record = await ops.findBySignature("0xsig1", KEY_ID_ABC);
		expect(record).not.toBeNull();
		expect(record?.notBefore).toBe(0);
		expect(record?.signatureHash).toBe(getErc8128SignatureHash("0xsig1"));
	});

	it("returns null for non-existent signature", async () => {
		const { adapter } = createMockAdapter();
		const ops = createDBInvalidationOps(adapter);
		expect(await ops.findBySignature("0xmissing", KEY_ID_ABC)).toBeNull();
	});

	it("ignores expired signature invalidations", async () => {
		vi.useFakeTimers();
		try {
			const { adapter } = createMockAdapter();
			const ops = createDBInvalidationOps(adapter);

			await ops.upsertSignatureInvalidation(KEY_ID_ABC, "0xsig1", 1);
			expect(await ops.findBySignature("0xsig1", KEY_ID_ABC)).not.toBeNull();
			vi.advanceTimersByTime(1100);
			expect(await ops.findBySignature("0xsig1", KEY_ID_ABC)).toBeNull();
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("secondaryStorage invalidation ops", () => {
	it("stores and retrieves per-keyId notBefore", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);

		await ops.upsertKeyIdNotBefore(KEY_ID_ABC, 1500);
		const records = await ops.findByKeyId(KEY_ID_ABC);
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(1500);
	});

	it("stores and retrieves per-signature invalidation", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);

		await ops.upsertSignatureInvalidation(KEY_ID_ABC, "0xsig1", 300);
		const record = await ops.findBySignature("0xsig1", KEY_ID_ABC);
		expect(record).not.toBeNull();
		expect(record?.signatureHash).toBe(getErc8128SignatureHash("0xsig1"));
	});

	it("returns empty array for missing keyId", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);
		expect(await ops.findByKeyId("missing")).toEqual([]);
	});

	it("returns null for missing signature", async () => {
		const { storage } = createMockStorage();
		const ops = createSecondaryStorageInvalidationOps(storage, 3600);
		expect(await ops.findBySignature("0xmissing", KEY_ID_ABC)).toBeNull();
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

		await ops.upsertKeyIdNotBefore("key", 1000);
		await ops.upsertSignatureInvalidation(KEY_ID_ABC, "0xsig", 300);
		expect(await ops.findByKeyId("key")).toEqual([]);
		expect(await ops.findBySignature("0xsig", KEY_ID_ABC)).toBeNull();
	});

	it("respects TTL expiry", async () => {
		vi.useFakeTimers();
		try {
			const { storage } = createMockStorage();
			const ops = createSecondaryStorageInvalidationOps(storage, 1);

			await ops.upsertKeyIdNotBefore(KEY_ID_ABC, 1000, 1);
			expect(await ops.findByKeyId(KEY_ID_ABC)).toHaveLength(1);

			vi.advanceTimersByTime(1100);
			expect(await ops.findByKeyId(KEY_ID_ABC)).toEqual([]);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("dual invalidation ops", () => {
	it("writes to both DB and secondaryStorage", async () => {
		const { adapter } = createMockAdapter();
		const { storage } = createMockStorage();
		const nowSec = Math.floor(Date.now() / 1000);

		const dbOps = createDBInvalidationOps(adapter);
		const ssOps = createSecondaryStorageInvalidationOps(storage, 3600);
		const dualOps = createDualInvalidationOps(dbOps, ssOps);

		await dualOps.upsertKeyIdNotBefore(KEY_ID_ABC, nowSec);
		expect(await dbOps.findByKeyId(KEY_ID_ABC)).toHaveLength(1);
		expect(await ssOps.findByKeyId(KEY_ID_ABC)).toHaveLength(1);
	});

	it("reads from secondaryStorage first, falls back to DB", async () => {
		const { adapter } = createMockAdapter();
		const { storage } = createMockStorage();
		const nowSec = Math.floor(Date.now() / 1000);

		const dbOps = createDBInvalidationOps(adapter);
		const ssOps = createSecondaryStorageInvalidationOps(storage, 3600);
		const dualOps = createDualInvalidationOps(dbOps, ssOps);

		await dbOps.upsertKeyIdNotBefore(KEY_ID_DB_ONLY, nowSec);
		const records = await dualOps.findByKeyId(KEY_ID_DB_ONLY);
		expect(records).toHaveLength(1);
		expect(records[0]!.notBefore).toBe(nowSec);
	});

	it("prefers secondaryStorage over DB on read", async () => {
		const { adapter } = createMockAdapter();
		const { storage } = createMockStorage();

		const dbOps = createDBInvalidationOps(adapter);
		const ssOps = createSecondaryStorageInvalidationOps(storage, 3600);
		const dualOps = createDualInvalidationOps(dbOps, ssOps);

		await dbOps.upsertKeyIdNotBefore(KEY_ID_ABC, 100);
		await ssOps.upsertKeyIdNotBefore(KEY_ID_ABC, 200);

		const records = await dualOps.findByKeyId(KEY_ID_ABC);
		expect(records[0]!.notBefore).toBe(200);
	});
});
