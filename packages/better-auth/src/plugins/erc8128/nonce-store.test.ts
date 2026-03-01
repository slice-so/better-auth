import { describe, expect, it } from "vitest";
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
});
