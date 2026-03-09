import { describe, expect, it, vi } from "vitest";
import type {
	CacheValue,
	VerificationCacheAdapter,
} from "./verification-cache";
import { createVerificationCacheOps } from "./verification-cache";

const val = (overrides?: Partial<CacheValue>): CacheValue => ({
	verified: true,
	expires: Math.floor(Date.now() / 1000) + 300,
	...overrides,
});

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

function createMockAdapter() {
	const rows = new Map<
		string,
		{
			id: string;
			cacheKey: string;
			address: string;
			chainId: number;
			signatureHash: string;
			expiresAt: Date;
		}
	>();
	let nextId = 1;

	const adapter: VerificationCacheAdapter = {
		async findOne(args) {
			if (args.where.some((where) => where.field === "id")) {
				const id = String(args.where.find((where) => where.field === "id")?.value);
				return Array.from(rows.values()).find((row) => row.id === id) ?? null;
			}
			const cacheKey = String(
				args.where.find((where) => where.field === "cacheKey")?.value,
			);
			return rows.get(cacheKey) ?? null;
		},
		async create(args) {
			const row = {
				id: String(nextId++),
				cacheKey: String(args.data.cacheKey),
				address: String(args.data.address),
				chainId: Number(args.data.chainId),
				signatureHash: String(args.data.signatureHash),
				expiresAt: args.data.expiresAt as Date,
			};
			rows.set(row.cacheKey, row);
			return row;
		},
		async update(args) {
			const id = String(args.where.find((where) => where.field === "id")?.value);
			const row = Array.from(rows.values()).find((entry) => entry.id === id);
			if (row) {
				Object.assign(row, args.update);
			}
			return row ?? null;
		},
		async deleteMany(args) {
			if (args.where.some((where) => where.field === "cacheKey")) {
				const cacheKey = String(
					args.where.find((where) => where.field === "cacheKey")?.value,
				);
				return rows.delete(cacheKey) ? 1 : 0;
			}
			let deleted = 0;
			for (const row of Array.from(rows.values())) {
				if (
					args.where.every((where) => {
						if (where.field === "expiresAt" && where.operator === "lt") {
							return row.expiresAt < (where.value as Date);
						}
						return String((row as Record<string, unknown>)[where.field] ?? "") ===
							String(where.value ?? "");
					})
				) {
					rows.delete(row.cacheKey);
					deleted++;
				}
			}
			return deleted;
		},
	};

	return { rows, adapter };
}

describe("secondaryStorage cache ops", () => {
	it("stores and retrieves a value", async () => {
		const { storage } = createMockStorage();
		const ops = createVerificationCacheOps(
			"secondary-storage",
			storage,
			createMockAdapter().adapter,
			new Map(),
			100,
		);

		const v = val();
		await ops.set({
			key: "sig1",
			value: v,
			ttlSec: 300,
			address: "0xabc",
			chainId: 1,
			signatureHash: "0xhash",
			expiresAt: new Date(v.expires * 1000),
		});
		expect(await ops.get("sig1")).toEqual(v);
	});

	it("returns null for missing key", async () => {
		const { storage } = createMockStorage();
		const ops = createVerificationCacheOps(
			"secondary-storage",
			storage,
			createMockAdapter().adapter,
			new Map(),
			100,
		);

		expect(await ops.get("missing")).toBeNull();
	});

	it("deletes a value", async () => {
		const { storage } = createMockStorage();
		const ops = createVerificationCacheOps(
			"secondary-storage",
			storage,
			createMockAdapter().adapter,
			new Map(),
			100,
		);

		await ops.set({
			key: "sig1",
			value: val(),
			ttlSec: 300,
			address: "0xabc",
			chainId: 1,
			signatureHash: "0xhash",
			expiresAt: new Date(Date.now() + 300_000),
		});
		await ops.delete("sig1");
		expect(await ops.get("sig1")).toBeNull();
	});

	it("sweep is a no-op for TTL-backed storage", () => {
		const { storage } = createMockStorage();
		const ops = createVerificationCacheOps(
			"secondary-storage",
			storage,
			createMockAdapter().adapter,
			new Map(),
			100,
		);

		ops.sweep();
	});

	it("swallows errors gracefully", async () => {
		const brokenStorage = {
			async get() {
				throw new Error("fail");
			},
			async set() {
				throw new Error("fail");
			},
			async delete() {
				throw new Error("fail");
			},
		};
		const ops = createVerificationCacheOps(
			"secondary-storage",
			brokenStorage,
			createMockAdapter().adapter,
			new Map(),
			100,
		);

		await ops.set({
			key: "sig1",
			value: val(),
			ttlSec: 300,
			address: "0xabc",
			chainId: 1,
			signatureHash: "0xhash",
			expiresAt: new Date(Date.now() + 300_000),
		});
		expect(await ops.get("sig1")).toBeNull();
		await ops.delete("sig1");
	});
});

describe("database cache ops", () => {
	it("stores in both in-memory and DB, reads from memory first", async () => {
		const { adapter, rows } = createMockAdapter();
		const fallbackMap = new Map<string, CacheValue>();
		const ops = createVerificationCacheOps(
			"database",
			undefined,
			adapter,
			fallbackMap,
			100,
		);

		const v = val();
		await ops.set({
			key: "sig1",
			value: v,
			ttlSec: 300,
			address: "0xabc",
			chainId: 1,
			signatureHash: "0xhash",
			expiresAt: new Date(v.expires * 1000),
		});

		expect(fallbackMap.has("sig1")).toBe(true);
		expect(rows.has("sig1")).toBe(true);
		expect(await ops.get("sig1")).toEqual(v);
	});

	it("falls back to DB on in-memory miss", async () => {
		const { adapter } = createMockAdapter();
		const fallbackMap = new Map<string, CacheValue>();
		const ops = createVerificationCacheOps(
			"database",
			undefined,
			adapter,
			fallbackMap,
			100,
		);

		const v = val();
		await ops.set({
			key: "sig1",
			value: v,
			ttlSec: 300,
			address: "0xabc",
			chainId: 1,
			signatureHash: "0xhash",
			expiresAt: new Date(v.expires * 1000),
		});

		fallbackMap.clear();
		const result = await ops.get("sig1");
		expect(result).toEqual(v);
		expect(fallbackMap.has("sig1")).toBe(true);
	});

	it("returns null for missing key", async () => {
		const ops = createVerificationCacheOps(
			"database",
			undefined,
			createMockAdapter().adapter,
			new Map(),
			100,
		);

		expect(await ops.get("missing")).toBeNull();
	});

	it("deletes from both in-memory and DB", async () => {
		const { adapter, rows } = createMockAdapter();
		const fallbackMap = new Map<string, CacheValue>();
		const ops = createVerificationCacheOps(
			"database",
			undefined,
			adapter,
			fallbackMap,
			100,
		);

		await ops.set({
			key: "sig1",
			value: val(),
			ttlSec: 300,
			address: "0xabc",
			chainId: 1,
			signatureHash: "0xhash",
			expiresAt: new Date(Date.now() + 300_000),
		});
		await ops.delete("sig1");

		expect(fallbackMap.has("sig1")).toBe(false);
		expect(rows.has("sig1")).toBe(false);
	});

	it("enforces LRU eviction at max capacity", async () => {
		const fallbackMap = new Map<string, CacheValue>();
		const ops = createVerificationCacheOps(
			"database",
			undefined,
			createMockAdapter().adapter,
			fallbackMap,
			3,
		);

		for (const key of ["sig1", "sig2", "sig3", "sig4"]) {
			await ops.set({
				key,
				value: val(),
				ttlSec: 300,
				address: "0xabc",
				chainId: 1,
				signatureHash: `0x${key}`,
				expiresAt: new Date(Date.now() + 300_000),
			});
		}

		expect(fallbackMap.has("sig1")).toBe(false);
		expect(fallbackMap.has("sig4")).toBe(true);
		expect(fallbackMap.size).toBe(3);
	});

	it("sweep removes expired entries from in-memory", async () => {
		vi.useFakeTimers();
		try {
			const fallbackMap = new Map<string, CacheValue>();
			const ops = createVerificationCacheOps(
				"database",
				undefined,
				createMockAdapter().adapter,
				fallbackMap,
				100,
			);

			const nowSec = Math.floor(Date.now() / 1000);
			await ops.set({
				key: "sig-expired",
				value: val({ expires: nowSec + 1 }),
				ttlSec: 1,
				address: "0xabc",
				chainId: 1,
				signatureHash: "0xexpired",
				expiresAt: new Date((nowSec + 1) * 1000),
			});
			await ops.set({
				key: "sig-valid",
				value: val({ expires: nowSec + 3600 }),
				ttlSec: 3600,
				address: "0xabc",
				chainId: 1,
				signatureHash: "0xvalid",
				expiresAt: new Date((nowSec + 3600) * 1000),
			});

			vi.advanceTimersByTime(61_000);
			ops.sweep();

			expect(fallbackMap.has("sig-expired")).toBe(false);
			expect(fallbackMap.has("sig-valid")).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it("swallows DB errors gracefully", async () => {
		const brokenAdapter: VerificationCacheAdapter = {
			async findOne() {
				throw new Error("DB down");
			},
			async create() {
				throw new Error("DB down");
			},
			async update() {
				throw new Error("DB down");
			},
			async deleteMany() {
				throw new Error("DB down");
			},
		};
		const fallbackMap = new Map<string, CacheValue>();
		const ops = createVerificationCacheOps(
			"database",
			undefined,
			brokenAdapter,
			fallbackMap,
			100,
		);

		const v = val();
		await ops.set({
			key: "sig1",
			value: v,
			ttlSec: 300,
			address: "0xabc",
			chainId: 1,
			signatureHash: "0xhash",
			expiresAt: new Date(v.expires * 1000),
		});
		expect(fallbackMap.has("sig1")).toBe(true);
		expect(await ops.get("sig1")).toEqual(v);

		fallbackMap.clear();
		expect(await ops.get("sig1")).toBeNull();
		await ops.delete("sig1");
	});
});
