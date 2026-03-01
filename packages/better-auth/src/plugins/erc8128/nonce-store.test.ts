import { describe, expect, it, vi } from "vitest";
import { createAdapterNonceStore } from "./nonce-store";

describe("erc8128 nonce store", () => {
	it("consumes nonce only once", async () => {
		const table = new Map<string, { identifier: string; value: string; expiresAt: Date }>();
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

	it("respects TTL expiry when adapter does not return expired values", async () => {
		vi.useFakeTimers();
		try {
			const table = new Map<string, { identifier: string; value: string; expiresAt: Date }>();
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
