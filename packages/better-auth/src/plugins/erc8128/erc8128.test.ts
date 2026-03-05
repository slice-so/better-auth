import type { VerifyPolicy, VerifyResult } from "@slicekit/erc8128";
import { createVerifierClient, formatKeyId } from "@slicekit/erc8128";
import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { erc8128 } from "./index";
import { schema as erc8128Schema } from "./schema";
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
	fn: (args: {
		request: Request;
		policy?: VerifyPolicy;
		setHeaders?: (name: string, value: string) => void;
	}) => Promise<VerifyResult>,
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
	it("always registers full schema including invalidation table", () => {
		const base = erc8128({ verifyMessage: async () => true });
		expect(base.schema).toEqual(erc8128Schema);
		expect(base.schema.erc8128Invalidation).toBeDefined();

		const replayable = erc8128({
			verifyMessage: async () => true,
			routePolicy: { default: { replayable: true } },
		});
		expect(replayable.schema).toEqual(erc8128Schema);
	});

	describe("GET /.well-known/erc8128", () => {
		it("returns discovery metadata", async () => {
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						maxValiditySec: 120,
						clockSkewSec: 15,
					}),
				],
			});

			const { response, data } = await get(auth, "/.well-known/erc8128");
			expect(response.status).toBe(200);
			expect(data).toMatchObject({
				verification_endpoint: "http://localhost:3000/api/auth/erc8128/verify",
				max_validity_sec: 120,
				capabilities: {
					persistent_storage: true,
					request_bound_middleware_only: false,
				},
			});
			expect(data.invalidation_endpoint).toBeUndefined();
		});

		it("includes invalidation endpoint when replayable signatures are enabled", async () => {
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: {
							default: { replayable: true },
						},
					}),
				],
			});

			const { response, data } = await get(auth, "/.well-known/erc8128");
			expect(response.status).toBe(200);
			expect(data.invalidation_endpoint).toBe(
				"http://localhost:3000/api/auth/erc8128/invalidate",
			);
		});

		it("includes route_policies when routePolicy is configured and omits false entries", async () => {
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: {
							"GET /api/products/*": { replayable: true },
							"POST /api/orders": { replayable: false },
							"GET /api/public/*": false,
							default: { replayable: false },
						},
					}),
				],
			});

			const { response, data } = await get(auth, "/.well-known/erc8128");
			expect(response.status).toBe(200);
			expect(data.route_policies).toEqual({
				"GET /api/products/*": { replayable: true },
				"POST /api/orders": { replayable: false },
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

		it("returns structured 401 with Accept-Signature for invalid/expired/tampered signature", async () => {
			mockVerifier(async ({ setHeaders }) => {
				setHeaders?.(
					"Accept-Signature",
					'sig=("@method" "@target-uri");alg="eip191"',
				);
				return failResult("bad_signature");
			});
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const { response, data } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(401);
			expect(response.headers.get("accept-signature")).toContain("@method");
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "bad_signature",
			});
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

		it("rejects class-bound signatures even when non-replayable", async () => {
			mockVerifier(async () => failResult("not_request_bound"));
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const { response, data } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(401);
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "not_request_bound",
			});
		});

		it("rejects replayable signatures even when request-bound", async () => {
			mockVerifier(async () => failResult("replayable_not_allowed"));
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const { response, data } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(401);
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "replayable_not_allowed",
			});
		});

		it("accepts request-bound non-replayable signatures", async () => {
			mockVerifier(async () => okResult({ replayable: false }));
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const { response, data } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(200);
			expect(data.success).toBe(true);
		});
	});

	describe("hooks.before", () => {
		it("middleware verifies signature and upserts user but does not create a session", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const ctx = await auth.$context;

			const { data, response } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-valid-hook",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(response.status).toBe(200);
			// Middleware does not create sessions — only /verify does
			expect(data === null || data.session === null).toBe(true);

			// But user + wallet were created
			const wallets = await ctx.adapter.findMany<WalletAddress>({
				model: "walletAddress",
				where: [{ field: "address", operator: "eq", value: defaultAddress }],
			});
			expect(wallets).toHaveLength(1);
		});

		it("middleware creates user + wallet on first signed request without prior /verify", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			const ctx = await auth.$context;

			// No users other than the default test user
			const usersBefore = await ctx.adapter.findMany({ model: "user" });
			const walletsBefore = await ctx.adapter.findMany({
				model: "walletAddress",
			});
			expect(usersBefore).toHaveLength(1); // default test user
			expect(walletsBefore).toHaveLength(0);

			// Signed request to middleware — should auto-create user + wallet (no session)
			const { data, response } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-first",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(response.status).toBe(200);
			// Middleware never creates sessions
			expect(data === null || data.session === null).toBe(true);

			const usersAfter = await ctx.adapter.findMany({ model: "user" });
			const walletsAfter = await ctx.adapter.findMany<WalletAddress>({
				model: "walletAddress",
				where: [{ field: "address", operator: "eq", value: defaultAddress }],
			});
			const accounts = await ctx.adapter.findMany<{ providerId: string }>({
				model: "account",
				where: [{ field: "providerId", operator: "eq", value: "erc8128" }],
			});

			expect(usersAfter).toHaveLength(2); // default test user + new wallet user
			expect(walletsAfter).toHaveLength(1);
			expect(walletsAfter[0]?.isPrimary).toBe(true);
			expect(accounts).toHaveLength(1);
		});

		it("middleware links same address on different chain to existing user", async () => {
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

			const ctx = await auth.$context;

			// First signed request — creates user on chain 1
			await get(auth, "/get-session", {
				headers: {
					signature: "sig-chain1",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});

			// Second signed request — same address, different chain
			await get(auth, "/get-session", {
				headers: {
					signature: "sig-chain137",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});

			const wallets = await ctx.adapter.findMany<WalletAddress>({
				model: "walletAddress",
				where: [{ field: "address", operator: "eq", value: defaultAddress }],
			});
			expect(wallets).toHaveLength(2);
			expect(wallets.find((w) => w.chainId === 1)?.isPrimary).toBe(true);
			expect(wallets.find((w) => w.chainId === 137)?.isPrimary).toBe(false);

			// Same user for both
			expect(wallets[0]?.userId).toBe(wallets[1]?.userId);
		});

		it("middleware with anonymous: false silently passes through for unknown wallets (no email)", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						anonymous: false,
					}),
				],
			});

			const ctx = await auth.$context;

			// Middleware can't provide an email, so findOrCreateWalletUser returns null
			const { data, response } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-anon",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(response.status).toBe(200);
			// No session — user creation failed (no email)
			expect(data === null || data.session === null).toBe(true);

			// No wallet created
			const wallets = await ctx.adapter.findMany({
				model: "walletAddress",
				where: [{ field: "address", operator: "eq", value: defaultAddress }],
			});
			expect(wallets).toHaveLength(0);
		});

		it("request without signature headers passes through without interference", async () => {
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

		it("invalid signature passes through and falls back to session cookie", async () => {
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
					signature: "bad-sig",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
					cookie,
				},
			});
			expect(response.status).toBe(200);
			expect(data.session).toBeDefined();
			expect(data.user).toBeDefined();
		});

		it("routePolicy exact match requires auth and returns structured 401 + Accept-Signature on failure", async () => {
			mockVerifier(async ({ request, setHeaders }) => {
				if (request.url.endsWith("/verify")) {
					return okResult();
				}
				setHeaders?.(
					"Accept-Signature",
					'sig=("@method" "@target-uri");alg="eip191"',
				);
				return failResult("expired");
			});

			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: {
							"GET /api/auth/get-session": { replayable: false },
						},
					}),
				],
			});

			const { response, data } = await get(auth, "/get-session", {
				headers: {
					signature: "bad-sig",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(response.status).toBe(401);
			expect(response.headers.get("accept-signature")).toContain("@method");
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "expired",
			});
		});

		it("routePolicy exact match passes through on valid signature", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: {
							"GET /api/auth/get-session": { replayable: false },
						},
					}),
				],
			});

			// Valid signature — middleware verifies and allows through (no session created)
			const { response } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-ok",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(response.status).toBe(200);
		});

		it("routePolicy wildcard + false skips verification entirely", async () => {
			const verifySpy = vi.fn(async () => okResult());
			vi.mocked(createVerifierClient).mockImplementation(() => ({
				verifyRequest: verifySpy,
			}));

			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: {
							"GET /api/auth/*": false,
						},
					}),
				],
			});

			const { response } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-skip",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(response.status).toBe(200);
			expect(verifySpy).not.toHaveBeenCalled();
		});

		it("routePolicy default requires auth for unmatched routes", async () => {
			mockVerifier(async () => failResult("not_request_bound"));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: {
							default: { replayable: false },
						},
					}),
				],
			});

			const { response, data } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-fail",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(response.status).toBe(401);
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "not_request_bound",
			});
		});

		it("session-first (default): skips signature verification when session cookie is present", async () => {
			const verifySpy = vi.fn(async () => okResult());
			vi.mocked(createVerifierClient).mockImplementation(() => ({
				verifyRequest: verifySpy,
			}));
			const { auth } = await getTestInstance({
				plugins: [erc8128({ verifyMessage: async () => true })],
			});

			// Create a session via /verify
			const verified = await post(auth, "/erc8128/verify");
			const cookie = cookieFromSetCookie(
				verified.response.headers.get("set-cookie"),
			);

			verifySpy.mockClear();

			// Request with both cookie and signature headers — session-first should skip verification
			const { response, data } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-skipped",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
					cookie,
				},
			});
			expect(response.status).toBe(200);
			expect(data.session).toBeDefined();
			expect(verifySpy).not.toHaveBeenCalled();
		});

		it("signature-first: verifies signature even when session cookie is present", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						authPrecedence: "signature-first",
					}),
				],
			});

			// Create a session via /verify
			const verified = await post(auth, "/erc8128/verify");
			const cookie = cookieFromSetCookie(
				verified.response.headers.get("set-cookie"),
			);

			const verifySpy = vi.fn(async () => okResult());
			vi.mocked(createVerifierClient).mockImplementation(() => ({
				verifyRequest: verifySpy,
			}));

			// Request with both cookie and signature headers — should still verify
			const { response } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-verified",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
					cookie,
				},
			});
			expect(response.status).toBe(200);
			expect(verifySpy).toHaveBeenCalled();
		});

		it("reject-on-mismatch: passes when session and signature resolve to the same user", async () => {
			mockVerifier(async () => okResult());
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						authPrecedence: "reject-on-mismatch",
					}),
				],
			});

			// Create a session via /verify (user created from defaultAddress)
			const verified = await post(auth, "/erc8128/verify");
			const cookie = cookieFromSetCookie(
				verified.response.headers.get("set-cookie"),
			);
			expect(verified.response.status).toBe(200);

			// Request with cookie + same wallet signature — should pass
			const { response, data } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-same",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
					cookie,
				},
			});
			expect(response.status).toBe(200);
			expect(data.session).toBeDefined();
		});

		it("reject-on-mismatch: returns 401 when session and signature resolve to different users", async () => {
			const otherAddress =
				"0x0000000000000000000000000000000000001234" as const;
			let call = 0;
			mockVerifier(async () => {
				call += 1;
				// First call: /verify creates session for defaultAddress
				if (call === 1) return okResult();
				// Second call: middleware verifies as otherAddress
				return okResult({
					address: otherAddress,
					keyId: formatKeyId(defaultChainId, otherAddress),
				});
			});

			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						authPrecedence: "reject-on-mismatch",
					}),
				],
			});

			// Create session for defaultAddress
			const verified = await post(auth, "/erc8128/verify");
			const cookie = cookieFromSetCookie(
				verified.response.headers.get("set-cookie"),
			);
			expect(verified.response.status).toBe(200);

			// Request with cookie (defaultAddress user) + signature (otherAddress) — mismatch
			const { response, data } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-different",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
					cookie,
				},
			});
			expect(response.status).toBe(401);
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "identity_mismatch",
			});
		});

		it("unmatched route without routePolicy.default uses opportunistic fallthrough", async () => {
			mockVerifier(async ({ request }) => {
				if (request.url.endsWith("/verify")) {
					return okResult();
				}
				return failResult("bad_signature");
			});
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: {
							"POST /api/auth/erc8128/verify": { replayable: false },
						},
					}),
				],
			});

			const verified = await post(auth, "/erc8128/verify");
			const cookie = cookieFromSetCookie(
				verified.response.headers.get("set-cookie"),
			);
			const { response, data } = await get(auth, "/get-session", {
				headers: {
					signature: "sig-bad",
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
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
						routePolicy: { default: { replayable: true } },
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

		it("replayable request to invalidation endpoint returns structured 401 with Accept-Signature", async () => {
			mockVerifier(async ({ setHeaders }) => {
				setHeaders?.(
					"Accept-Signature",
					'sig=("@method" "@target-uri");alg="eip191"',
				);
				return failResult("replayable_not_allowed");
			});
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const { response, data } = await post(auth, "/erc8128/invalidate");
			expect(response.status).toBe(401);
			expect(response.headers.get("accept-signature")).toContain("@method");
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "replayable_not_allowed",
			});
		});

		it("per-signature invalidation creates DB record and evicts from cache", async () => {
			const keyId = formatKeyId(defaultChainId, defaultAddress);
			const sigToInvalidate = "0xdeadbeef";
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
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const { response, data } = await post(auth, "/erc8128/invalidate", {
				body: { signature: sigToInvalidate },
			});
			expect(response.status).toBe(200);
			expect(data.success).toBe(true);
			expect(data.invalidatedSignature).toBe(sigToInvalidate);
			// DB record should be created with the signature field
			const ctx = await auth.$context;
			const dbRecords = await ctx.adapter.findMany<{
				signature?: string;
			}>({
				model: "erc8128Invalidation",
			});
			expect(dbRecords).toHaveLength(1);
			expect(dbRecords[0]?.signature).toBe(sigToInvalidate);
		});

		it("rejects providing both notBefore and signature", async () => {
			mockVerifier(async () => okResult({ replayable: false }));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const { response } = await post(auth, "/erc8128/invalidate", {
				body: {
					notBefore: Math.floor(Date.now() / 1000) + 10,
					signature: "0xdeadbeef",
				},
			});
			// Zod refinement rejects mutually exclusive fields
			expect(response.status).not.toBe(200);
		});

		it("per-signature invalidation is checked via parallel DB query in middleware", async () => {
			const keyId = formatKeyId(defaultChainId, defaultAddress);
			const sig = "0xdeadbeefcafe";

			mockVerifier(async ({ request }) => {
				if (request.url.endsWith("/verify")) {
					return okResult({ keyId, replayable: false });
				}
				if (request.url.endsWith("/invalidate")) {
					return okResult({ keyId, replayable: false });
				}
				return okResult({ keyId, replayable: true });
			});

			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const headers = {
				signature: sig,
				"signature-input": 'sig=("@method" "@target-uri" "@authority")',
			};

			// Should pass through before invalidation (middleware verifies but doesn't create session)
			const before = await get(auth, "/get-session", { headers });
			expect(before.response.status).toBe(200);

			// Invalidate the specific signature
			const inv = await post(auth, "/erc8128/invalidate", {
				body: { signature: sig },
			});
			expect(inv.data.invalidatedSignature).toBe(sig);

			// After invalidation, parallel DB check rejects it
			const after = await get(auth, "/get-session", { headers });
			expect(after.response.status).toBe(401);
			expect(after.data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "signature_invalidated",
			});
		});

		it("per-signature invalidation only affects the caller's own signatures", async () => {
			const userAAddress =
				"0x000000000000000000000000000000000000aaaa" as const;
			const userBAddress =
				"0x000000000000000000000000000000000000bbbb" as const;
			const userAKeyId = formatKeyId(defaultChainId, userAAddress);
			const userBKeyId = formatKeyId(defaultChainId, userBAddress);
			const userBSig = "0xuserbsignature";

			mockVerifier(async ({ request }) => {
				// User A calls /invalidate trying to invalidate User B's signature
				if (request.url.endsWith("/invalidate")) {
					return okResult({
						address: userAAddress,
						keyId: userAKeyId,
						replayable: false,
					});
				}
				// User B's replayable signature in middleware
				return okResult({
					address: userBAddress,
					keyId: userBKeyId,
					replayable: true,
				});
			});

			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			// User B's signature works before invalidation attempt
			const before = await get(auth, "/get-session", {
				headers: {
					signature: userBSig,
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(before.response.status).toBe(200);

			// User A tries to invalidate User B's signature
			const inv = await post(auth, "/erc8128/invalidate", {
				body: { signature: userBSig },
			});
			expect(inv.data.success).toBe(true);

			// User B's signature should still work — invalidation was by a different keyId
			const after = await get(auth, "/get-session", {
				headers: {
					signature: userBSig,
					"signature-input": 'sig=("@method" "@target-uri" "@authority")',
				},
			});
			expect(after.response.status).toBe(200);

			// Verify User B's wallet was still created (middleware passed through)
			const ctx = await auth.$context;
			const wallets = await ctx.adapter.findMany<WalletAddress>({
				model: "walletAddress",
				where: [{ field: "address", operator: "eq", value: userBAddress }],
			});
			expect(wallets).toHaveLength(1);
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
						routePolicy: { default: { replayable: true } },
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

		it("rejects class-bound signatures even when non-replayable", async () => {
			mockVerifier(async () => failResult("not_request_bound"));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const { response, data } = await post(auth, "/erc8128/invalidate");
			expect(response.status).toBe(401);
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "not_request_bound",
			});
		});

		it("rejects replayable signatures even when request-bound", async () => {
			mockVerifier(async () => failResult("replayable_not_allowed"));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const { response, data } = await post(auth, "/erc8128/invalidate");
			expect(response.status).toBe(401);
			expect(data).toMatchObject({
				error: "erc8128_verification_failed",
				reason: "replayable_not_allowed",
			});
		});

		it("accepts request-bound non-replayable signatures", async () => {
			mockVerifier(async () => okResult({ replayable: false }));
			const { auth } = await getTestInstance({
				plugins: [
					erc8128({
						verifyMessage: async () => true,
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const { response, data } = await post(auth, "/erc8128/invalidate");
			expect(response.status).toBe(200);
			expect(data.success).toBe(true);
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
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const headers = {
				signature: "sig-replayable",
				"signature-input": 'sig=("@method" "@target-uri" "@authority")',
			};
			const first = await get(auth, "/get-session", { headers });
			const second = await get(auth, "/get-session", { headers });

			expect(first.response.status).toBe(200);
			expect(second.response.status).toBe(200);
			expect(verifySpy).toHaveBeenCalledTimes(1); // only first request triggers full verification; second uses cache
		});

		it("lazily sweeps expired cache entries on cache access", async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

			try {
				const verifySpy = vi.fn(async ({ request }: { request: Request }) => {
					const now = Math.floor(Date.now() / 1000);
					return okResult({
						replayable: true,
						created: now,
						expires: now + 30,
					});
				});

				vi.mocked(createVerifierClient).mockImplementation(() => ({
					verifyRequest: verifySpy,
				}));

				const { auth } = await getTestInstance({
					plugins: [
						erc8128({
							verifyMessage: async () => true,
							routePolicy: { default: { replayable: true } },
						}),
					],
				});

				await get(auth, "/get-session", {
					headers: { signature: "sig-a", "signature-input": 'sig=("@method" "@target-uri" "@authority")' },
				});

				vi.advanceTimersByTime(61_000);

				await get(auth, "/get-session", {
					headers: { signature: "sig-a", "signature-input": 'sig=("@method" "@target-uri" "@authority")' },
				});

				const sigAVerifications = verifySpy.mock.calls.filter(
					([arg]) => arg.request.headers.get("signature") === "sig-a",
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
						routePolicy: { default: { replayable: true } },
					}),
				],
			});

			const { response } = await post(auth, "/erc8128/verify");
			expect(response.status).toBe(401);
		});
	});
});
