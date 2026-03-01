import type { VerifyResult } from "@slicekit/erc8128";
import { createVerifierClient, formatKeyId } from "@slicekit/erc8128";
import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { erc8128 } from "./index";
import { schema as erc8128Schema, walletAddressSchema } from "./schema";
import type { WalletAddress } from "./types";

vi.mock("@slicekit/erc8128", async () => {
	const actual =
		await vi.importActual<typeof import("@slicekit/erc8128")>(
			"@slicekit/erc8128",
		);

	return {
		...actual,
		createVerifierClient: vi.fn(),
	};
});

const defaultAddress = "0x000000000000000000000000000000000000dEaD" as const;
const defaultChainId = 1;

function okResult(args?: {
	address?: `0x${string}`;
	chainId?: number;
	created?: number;
	expires?: number;
	replayable?: boolean;
	keyId?: string;
}): VerifyResult {
	const address = args?.address ?? defaultAddress;
	const chainId = args?.chainId ?? defaultChainId;
	const keyId = args?.keyId ?? formatKeyId(chainId, address);
	const created = args?.created ?? Math.floor(Date.now() / 1000);
	const expires = args?.expires ?? created + 300;

	return {
		ok: true,
		address,
		chainId,
		label: "eth",
		components: ["@method", "@target-uri", "@authority"],
		params: {
			created,
			expires,
			keyid: keyId,
		},
		replayable: args?.replayable ?? false,
		binding: "class-bound",
	};
}

function failResult(
	reason: Extract<VerifyResult, { ok: false }>["reason"],
): VerifyResult {
	return {
		ok: false,
		reason,
	};
}

function mockVerifier(
	fn: (args: { request: Request }) => Promise<VerifyResult>,
) {
	vi.mocked(createVerifierClient).mockImplementation(() => ({
		verifyRequest: vi.fn(fn),
	}));
}

interface TestAuth {
	handler: (request: Request) => Promise<Response>;
}

async function post(
	auth: TestAuth,
	path: string,
	init?: { headers?: HeadersInit; body?: Record<string, unknown> },
) {
	const response = await auth.handler(
		new Request(`http://localhost:3000/api/auth${path}`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				...(init?.headers ?? {}),
			},
			body: JSON.stringify(init?.body ?? {}),
		}),
	);
	const data = await response.json();
	return { response, data };
}

async function get(
	auth: TestAuth,
	path: string,
	init?: { headers?: HeadersInit },
) {
	const response = await auth.handler(
		new Request(`http://localhost:3000/api/auth${path}`, {
			method: "GET",
			headers: init?.headers,
		}),
	);
	const data = await response.json();
	return { response, data };
}

function cookieFromSetCookie(setCookie: string | null) {
	if (!setCookie) return "";
	return setCookie.split(";")[0] ?? "";
}

describe("erc8128 plugin", () => {
	it("registers walletAddress schema by default and invalidation schema when allowReplayable=true", () => {
		const base = erc8128({ verifyMessage: async () => true });
		expect(base.schema).toEqual(walletAddressSchema);

		const replayable = erc8128({
			verifyMessage: async () => true,
			allowReplayable: true,
		});
		expect(replayable.schema).toEqual(erc8128Schema);
		expect(replayable.schema.erc8128Invalidation).toBeDefined();
	});

	describe("GET /.well-known/erc8128", () => {
		it("returns discovery metadata", async () => {
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						maxValiditySec: 120,
						clockSkewSec: 15,
						createSession: false,
					}),
				],
			});

			const { response, data } = await get(auth, "/.well-known/erc8128");
			expect(response.status).toBe(200);
			expect(data).toEqual({
				verification_endpoint: "http://localhost:3000/api/auth/erc8128/verify",
				signing_algorithms: ["eip191"],
				account_types: ["eoa", "erc1271"],
				replay_protection: {
					non_replayable: true,
					replayable: false,
				},
				max_validity_sec: 120,
				clock_skew_sec: 15,
				keyid_format: "erc8128:<chainId>:<address>",
				signature_scheme: "rfc9421",
				default_binding: "request-bound",
				session_creation: false,
			});
			expect(data.invalidation_endpoint).toBeUndefined();
		});

		it("includes invalidation endpoint when replayable signatures are enabled", async () => {
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						allowReplayable: true,
					}),
				],
			});

			const { response, data } = await get(auth, "/.well-known/erc8128");
			expect(response.status).toBe(200);
			expect(data.invalidation_endpoint).toBe(
				"http://localhost:3000/api/auth/erc8128/invalidate",
			);
			expect(data.replay_protection).toEqual({
				non_replayable: true,
				replayable: true,
			});
		});
	});

	describe("POST /erc8128/verify", () => {
		it("creates user + walletAddress + account + session and sets cookie for valid signature", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const { response, data } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(200);
			expect(data.success).toBe(true);
			expect(data.token).toBeDefined();
			expect(response.headers.get("set-cookie")).toContain(
				"better-auth.session_token=",
			);

			const ctx = await auth.$context;
			const users = await ctx.adapter.findMany({ model: "user" });
			const walletAddresses = await ctx.adapter.findMany<WalletAddress>({
				model: "walletAddress",
				where: [{ field: "address", operator: "eq", value: defaultAddress }],
			});
			const accounts = await ctx.adapter.findMany<{ providerId: string }>({
				model: "account",
			});
			const sessions = await ctx.adapter.findMany({ model: "session" });

			expect(users.length).toBe(2); // default test user + new wallet user
			expect(walletAddresses).toHaveLength(1);
			expect(accounts.some((a) => a.providerId === "erc8128")).toBe(true);
			expect(sessions.length).toBeGreaterThan(0);
		});

		it("reuses existing user for same address+chain and does not duplicate user", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const first = await post(auth, "/erc8128/verify");
			const second = await post(auth, "/erc8128/verify");
			expect(first.response.status).toBe(200);
			expect(second.response.status).toBe(200);
			expect(second.data.user.id).toBe(first.data.user.id);

			const ctx = await auth.$context;
			const walletAddresses = await ctx.adapter.findMany({
				model: "walletAddress",
				where: [
					{ field: "address", operator: "eq", value: defaultAddress },
					{ field: "chainId", operator: "eq", value: defaultChainId },
				],
			});
			expect(walletAddresses).toHaveLength(1);
		});

		it("links same address on different chain to existing user and adds walletAddress record", async () => {
			let call = 0;
			mockVerifier(async () => {
				call += 1;
				return call === 1
					? okResult({ chainId: 1 })
					: okResult({ chainId: 137, keyId: formatKeyId(137, defaultAddress) });
			});
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const eth = await post(auth, "/erc8128/verify");
			const polygon = await post(auth, "/erc8128/verify");
			expect(eth.data.user.id).toBe(polygon.data.user.id);

			const ctx = await auth.$context;
			const walletAddresses = await ctx.adapter.findMany<WalletAddress>({
				model: "walletAddress",
				where: [{ field: "address", operator: "eq", value: defaultAddress }],
			});
			expect(walletAddresses).toHaveLength(2);
			expect(walletAddresses.find((w) => w.chainId === 1)?.isPrimary).toBe(
				true,
			);
			expect(walletAddresses.find((w) => w.chainId === 137)?.isPrimary).toBe(
				false,
			);
		});

		it("returns 401 for invalid/expired/tampered signature", async () => {
			mockVerifier(async () => failResult("bad_signature"));
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const { response } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(401);
		});

		it("returns 401 for replayed nonce", async () => {
			let call = 0;
			mockVerifier(async () => {
				call += 1;
				return call === 1 ? okResult() : failResult("replay");
			});
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const first = await post(auth, "/erc8128/verify");
			const second = await post(auth, "/erc8128/verify");
			expect(first.response.status).toBe(200);
			expect(second.response.status).toBe(401);
		});
	});

	describe("hooks.before", () => {
		it("valid ERC-8128 Authorization header authenticates request via middleware", async () => {
			const signature = "sig-valid-hook";
			const verifySpy = vi.fn(async () => okResult({ replayable: true }));
			vi.mocked(createVerifierClient).mockImplementation(() => ({
				verifyRequest: verifySpy,
			}));

			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						allowReplayable: true,
					}),
				],
			});

			// Ensure wallet exists before hook-based auth tries to create a session
			await post(auth, "/erc8128/verify");

			const { data, response } = await get(auth, "/get-session", {
				headers: {
					authorization: "ERC-8128 auth",
					signature,
				},
			});
			expect(response.status).toBe(200);
			expect(data.session).toBeDefined();
			expect(data.user).toBeDefined();
		});

		it("request without ERC-8128 header passes through without interference", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const { data, response } = await get(auth, "/get-session");
			expect(response.status).toBe(200);
			expect(
				data === null || (data.session === null && data.user === null),
			).toBe(true);
		});

		it("invalid ERC-8128 header passes through and falls back to session cookie", async () => {
			let call = 0;
			mockVerifier(async () => {
				call += 1;
				return call === 1 ? okResult() : failResult("bad_signature");
			});
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const verified = await post(auth, "/erc8128/verify");
			const cookie = cookieFromSetCookie(
				verified.response.headers.get("set-cookie"),
			);
			const { data, response } = await get(auth, "/get-session", {
				headers: {
					authorization: "ERC-8128 invalid",
					signature: "bad-sig",
					cookie,
				},
			});
			expect(response.status).toBe(200);
			expect(data.session).toBeDefined();
			expect(data.user).toBeDefined();
		});
	});

	describe("POST /erc8128/invalidate", () => {
		it("valid non-replayable request sets notBefore for keyId", async () => {
			const keyId = formatKeyId(defaultChainId, defaultAddress);
			mockVerifier(async ({ request }) => {
				if (request.url.endsWith("/invalidate")) {
					return okResult({ keyId, replayable: false });
				}
				return okResult({ keyId, replayable: true });
			});

			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						allowReplayable: true,
					}),
				],
			});

			const notBefore = Math.floor(Date.now() / 1000) + 10;
			const { response, data } = await post(auth, "/erc8128/invalidate", {
				body: { notBefore },
			});
			expect(response.status).toBe(200);
			expect(data.success).toBe(true);
			expect(data.invalidatedBefore).toBe(notBefore);

			const ctx = await auth.$context;
			const invalidation = await ctx.adapter.findOne<{ notBefore: number }>({
				model: "erc8128Invalidation",
				where: [{ field: "keyId", operator: "eq", value: keyId }],
			});
			expect(invalidation?.notBefore).toBe(notBefore);
		});

		it("replayable request to invalidation endpoint returns 401", async () => {
			mockVerifier(async () => failResult("replayable_not_allowed"));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						allowReplayable: true,
					}),
				],
			});

			const { response } = await post(auth, "/erc8128/invalidate");
			expect(response.status).toBe(401);
		});

		it("after invalidation, old replayable signatures are rejected", async () => {
			const keyId = formatKeyId(defaultChainId, defaultAddress);
			const now = Math.floor(Date.now() / 1000);
			mockVerifier(async ({ request }) => {
				if (request.url.endsWith("/verify")) {
					return okResult({ keyId, replayable: true, created: now - 20 });
				}
				if (request.url.endsWith("/invalidate")) {
					return okResult({ keyId, replayable: false });
				}
				return failResult("replayable_not_before");
			});
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						allowReplayable: true,
					}),
				],
			});

			// valid replayable verification
			const first = await post(auth, "/erc8128/verify");
			expect(first.response.status).toBe(200);

			// set invalidation cutoff newer than replayable "created"
			const invalidatedBefore = now - 10;
			const invalidation = await post(auth, "/erc8128/invalidate", {
				body: { notBefore: invalidatedBefore },
			});
			expect(invalidation.response.status).toBe(200);

			// replayable verify is now rejected by verifier policy
			vi.mocked(createVerifierClient).mockImplementation(() => ({
				verifyRequest: vi.fn(async ({ request }) => {
					if (request.url.endsWith("/verify")) {
						return failResult("replayable_not_before");
					}
					return okResult({ keyId, replayable: false });
				}),
			}));

			const second = await post(auth, "/erc8128/verify");
			expect(second.response.status).toBe(401);
		});
	});

	describe("replayable signature caching", () => {
		it("accepts same replayable signature multiple times within window", async () => {
			const verifySpy = vi.fn(async () => okResult({ replayable: true }));
			vi.mocked(createVerifierClient).mockImplementation(() => ({
				verifyRequest: verifySpy,
			}));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						allowReplayable: true,
					}),
				],
			});

			await post(auth, "/erc8128/verify"); // create wallet user

			const headers = {
				authorization: "ERC-8128 replayable",
				signature: "sig-replayable",
			};
			const first = await get(auth, "/get-session", { headers });
			const second = await get(auth, "/get-session", { headers });

			expect(first.data.session).toBeDefined();
			expect(second.data.session).toBeDefined();
			expect(verifySpy).toHaveBeenCalledTimes(2); // one for /verify + one for first /get-session
		});


		it("lazily sweeps expired cache entries on cache access", async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

			try {
				const verifySpy = vi.fn(async ({ request }: { request: Request }) => {
					if (request.url.endsWith("/verify")) {
						return okResult({ replayable: false });
					}
					const now = Math.floor(Date.now() / 1000);
					return okResult({ replayable: true, created: now, expires: now + 30 });
				});

				vi.mocked(createVerifierClient).mockImplementation(() => ({
					verifyRequest: verifySpy,
				}));

				const { auth } = await getTestInstance({
					plugins: [
						erc8128({
							verifyMessage: async () => true,
							allowReplayable: true,
						}),
					],
				});

				await post(auth, "/erc8128/verify");

				await get(auth, "/get-session", {
					headers: { authorization: "ERC-8128 replayable", signature: "sig-a" },
				});

				vi.advanceTimersByTime(61_000);

				await get(auth, "/get-session", {
					headers: { authorization: "ERC-8128 replayable", signature: "sig-a" },
				});

				const sigAVerifications = verifySpy.mock.calls.filter(([arg]) =>
					arg.request.headers.get("signature") === "sig-a",
				);
				expect(sigAVerifications).toHaveLength(2);
			} finally {
				vi.useRealTimers();
			}
		});

		it("rejects expired replayable signatures", async () => {
			mockVerifier(async () => failResult("expired"));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						allowReplayable: true,
					}),
				],
			});

			const { response } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(401);
		});
	});
});
