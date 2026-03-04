import { describe, expect, it, vi } from "vitest";
import {
	createAdapterNonceStore,
	createDualNonceStore,
	createSecondaryStorageNonceStore,
} from "./nonce-store";

describe("erc8128 nonce store", () => {
	it("consumes nonce only once", async () => {
		const table = new Map<
			string,
			{ identifier: string; value: string; expiresAt: Date }
		>();
		const adapter = {
			async findVerificationValue(identifier: string) {
				const entry = table.get(identifier);
				return entry ? { id: identifier, ...entry } : null;
			},
			async createVerificationValue(data: {
				identifier: string;
				value: string;
				expiresAt: Date;
			}) {
				table.set(data.identifier, data);
			},
		};

		const store = createAdapterNonceStore(adapter);
		const first = await store.consume("nonce-key", 60);
		const second = await store.consume("nonce-key", 60);

		expect(first).toBe(true);
		expect(second).toBe(false);
	});

	it("falls back to in-memory map when adapter throws", async () => {
		const adapter = {
			async findVerificationValue() {
				throw new Error("DB down");
			},
			async createVerificationValue() {
				throw new Error("DB down");
			},
		};

		const store = createAdapterNonceStore(adapter);
		const first = await store.consume("fallback-key", 60);
		const second = await store.consume("fallback-key", 60);

		expect(first).toBe(true);
		expect(second).toBe(false);
	});

	it("respects TTL expiry when adapter does not return expired values", async () => {
		vi.useFakeTimers();
		try {
			const table = new Map<
				string,
				{ identifier: string; value: string; expiresAt: Date }
			>();
			const adapter = {
				async findVerificationValue(identifier: string) {
					const entry = table.get(identifier);
					if (!entry) return null;
					if (entry.expiresAt.getTime() <= Date.now()) {
						table.delete(identifier);
						return null;
					}
					return { id: identifier, ...entry };
				},
				async createVerificationValue(data: {
					identifier: string;
					value: string;
					expiresAt: Date;
				}) {
					table.set(data.identifier, data);
				},
			};

			const store = createAdapterNonceStore(adapter);
			expect(await store.consume("nonce-with-ttl", 1)).toBe(true);
			expect(await store.consume("nonce-with-ttl", 1)).toBe(false);

			vi.advanceTimersByTime(1100);
			expect(await store.consume("nonce-with-ttl", 1)).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("secondaryStorage nonce store", () => {
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

	it("consumes nonce only once", async () => {
		const { storage } = createMockStorage();
		const nonceStore = createSecondaryStorageNonceStore(storage);

		expect(await nonceStore.consume("ss-nonce-1", 60)).toBe(true);
		expect(await nonceStore.consume("ss-nonce-1", 60)).toBe(false);
	});

	it("allows reuse after TTL expiry", async () => {
		vi.useFakeTimers();
		try {
			const { storage } = createMockStorage();
			const nonceStore = createSecondaryStorageNonceStore(storage);

			expect(await nonceStore.consume("ss-ttl-nonce", 1)).toBe(true);
			expect(await nonceStore.consume("ss-ttl-nonce", 1)).toBe(false);

			vi.advanceTimersByTime(1100);
			expect(await nonceStore.consume("ss-ttl-nonce", 1)).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it("returns false when storage throws", async () => {
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

		const nonceStore = createSecondaryStorageNonceStore(storage);
		expect(await nonceStore.consume("err-nonce", 60)).toBe(false);
	});
});

describe("dual nonce store", () => {
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

	function createMockAdapterStore() {
		const table = new Map<
			string,
			{ identifier: string; value: string; expiresAt: Date }
		>();
		const adapter = {
			async findVerificationValue(identifier: string) {
				const entry = table.get(identifier);
				return entry ? { id: identifier, ...entry } : null;
			},
			async createVerificationValue(data: {
				identifier: string;
				value: string;
				expiresAt: Date;
			}) {
				table.set(data.identifier, data);
			},
		};
		return { table, adapter };
	}

	it("consumes in both stores", async () => {
		const { adapter } = createMockAdapterStore();
		const { storage, store } = createMockStorage();

		const dbStore = createAdapterNonceStore(adapter);
		const ssStore = createSecondaryStorageNonceStore(storage);
		const dual = createDualNonceStore(dbStore, ssStore);

		expect(await dual.consume("dual-nonce", 60)).toBe(true);

		// Both stores should have the nonce
		expect(store.size).toBeGreaterThan(0);

		// Second consume should fail
		expect(await dual.consume("dual-nonce", 60)).toBe(false);
	});

	it("rejects if already consumed in secondaryStorage", async () => {
		const { adapter } = createMockAdapterStore();
		const { storage } = createMockStorage();

		const ssStore = createSecondaryStorageNonceStore(storage);
		const dual = createDualNonceStore(
			createAdapterNonceStore(adapter),
			ssStore,
		);

		// Pre-consume in SS only
		await ssStore.consume("pre-consumed", 60);

		// Dual should reject
		expect(await dual.consume("pre-consumed", 60)).toBe(false);
	});
});
