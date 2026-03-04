import { describe, expect, it, vi } from "vitest";
import type {
	CacheValue,
	VerificationCacheAdapter,
} from "./verification-cache";
import { createVerificationCacheOps } from "./verification-cache";

const val = (overrides?: Partial<CacheValue>): CacheValue => ({
	address: "0xdead",
	chainId: 1,
	keyId: "erc8128:1:0xdead",
	expires: Math.floor(Date.now() / 1000) + 300,
	created: Math.floor(Date.now() / 1000),
	...overrides,
});

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

// ---------------------------------------------------------------------------
// Mock DB adapter
// ---------------------------------------------------------------------------
function createMockAdapter() {
	const rows = new Map<string, { value: string; expiresAt: Date }>();

	const adapter: VerificationCacheAdapter = {
		async findVerificationValue(identifier: string) {
			return rows.get(identifier) ?? null;
		},
		async createVerificationValue(data) {
			rows.set(data.identifier, {
				value: data.value,
				expiresAt: data.expiresAt,
			});
		},
		async deleteVerificationByIdentifier(identifier: string) {
			rows.delete(identifier);
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
		await ops.set("sig1", v, 300);
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

		await ops.set("sig1", val(), 300);
		await ops.delete("sig1");
		expect(await ops.get("sig1")).toBeNull();
	});

	it("evictByKeyId and sweep are no-ops", () => {
		const { storage } = createMockStorage();
		const ops = createVerificationCacheOps(
			"secondary-storage",
			storage,
			createMockAdapter().adapter,
			new Map(),
			100,
		);

		// Should not throw
		ops.evictByKeyId("key", 1000);
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

		await ops.set("sig1", val(), 300);
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
		await ops.set("sig1", v, 300);

		// In-memory
		expect(fallbackMap.has("sig1")).toBe(true);
		// DB
		expect(rows.has("erc8128:cache:sig1")).toBe(true);

		// Read hits memory (no DB call needed)
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
		await ops.set("sig1", v, 300);

		// Clear in-memory to force DB fallback
		fallbackMap.clear();
		const result = await ops.get("sig1");
		expect(result).toEqual(v);

		// Should now be back in memory
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

		await ops.set("sig1", val(), 300);
		await ops.delete("sig1");

		expect(fallbackMap.has("sig1")).toBe(false);
		expect(rows.has("erc8128:cache:sig1")).toBe(false);
	});

	it("evicts by keyId with notBefore", async () => {
		const fallbackMap = new Map<string, CacheValue>();
		const ops = createVerificationCacheOps(
			"database",
			undefined,
			createMockAdapter().adapter,
			fallbackMap,
			100,
		);

		const now = Math.floor(Date.now() / 1000);
		await ops.set("sig-old", val({ created: now - 100, keyId: "key1" }), 300);
		await ops.set("sig-new", val({ created: now + 100, keyId: "key1" }), 300);
		await ops.set("sig-other", val({ created: now - 100, keyId: "key2" }), 300);

		ops.evictByKeyId("key1", now);

		expect(fallbackMap.has("sig-old")).toBe(false);
		expect(fallbackMap.has("sig-new")).toBe(true);
		expect(fallbackMap.has("sig-other")).toBe(true);
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

		await ops.set("sig1", val(), 300);
		await ops.set("sig2", val(), 300);
		await ops.set("sig3", val(), 300);
		// This should evict sig1 (oldest)
		await ops.set("sig4", val(), 300);

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
			await ops.set("sig-expired", val({ expires: nowSec + 1 }), 1);
			await ops.set("sig-valid", val({ expires: nowSec + 3600 }), 3600);

			// Advance past sweep interval (60s) and past the expiry
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
			async findVerificationValue() {
				throw new Error("DB down");
			},
			async createVerificationValue() {
				throw new Error("DB down");
			},
			async deleteVerificationByIdentifier() {
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
		// set should still work (in-memory)
		await ops.set("sig1", v, 300);
		expect(fallbackMap.has("sig1")).toBe(true);

		// get from memory works
		expect(await ops.get("sig1")).toEqual(v);

		// get with no memory falls back to DB which fails gracefully
		fallbackMap.clear();
		expect(await ops.get("sig1")).toBeNull();

		// delete doesn't throw
		await ops.delete("sig1");
	});
});
