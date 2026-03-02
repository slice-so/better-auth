import type { NonceStore } from "@slicekit/erc8128";

interface VerificationAdapter {
	findVerificationValue(identifier: string): Promise<{
		id: string;
		identifier: string;
		value: string;
		expiresAt: Date;
	} | null>;
	createVerificationValue(data: {
		identifier: string;
		value: string;
		expiresAt: Date;
	}): Promise<unknown>;
}

export function createAdapterNonceStore(
	adapter: VerificationAdapter,
): NonceStore {
	const fallback = new Map<string, number>();

	const consumeFromFallback = (
		identifier: string,
		ttlSeconds: number,
	): boolean => {
		const now = Date.now();
		for (const [key, expiresAt] of fallback) {
			if (expiresAt <= now) {
				fallback.delete(key);
			}
		}

		const existing = fallback.get(identifier);
		if (existing && existing > now) {
			return false;
		}

		fallback.set(identifier, now + ttlSeconds * 1000);
		return true;
	};

	return {
		async consume(key: string, ttlSeconds: number): Promise<boolean> {
			const identifier = `erc8128:nonce:${key}`;

			try {
				const existing = await adapter.findVerificationValue(identifier);
				if (existing) {
					return false;
				}

				await adapter.createVerificationValue({
					identifier,
					value: "1",
					expiresAt: new Date(Date.now() + ttlSeconds * 1000),
				});

				return true;
			} catch {
				return consumeFromFallback(identifier, ttlSeconds);
			}
		},
	};
}
