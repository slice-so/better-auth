import type {
	EthHttpSigner,
	ServerConfig,
	SignerClient,
} from "@slicekit/erc8128";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@slicekit/erc8128", async () => {
	const actual =
		await vi.importActual<typeof import("@slicekit/erc8128")>(
			"@slicekit/erc8128",
		);
	return {
		...actual,
		createSignerClient: vi.fn(),
	};
});

import { createSignerClient, formatKeyId } from "@slicekit/erc8128";
import type { CachedSignature, Erc8128SignatureStore } from "./client";
import { erc8128Client } from "./client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const defaultAddress = "0x000000000000000000000000000000000000dEaD" as const;
const defaultChainId = 1;
const defaultKeyId = formatKeyId(defaultChainId, defaultAddress);
const BASE_URL = "http://localhost:3000/api/auth";

/** Default server config that allows replayable + class-bound. */
const REPLAYABLE_CONFIG: ServerConfig = {
	max_validity_sec: 300,
	route_policies: {
		default: { replayable: true, classBoundPolicies: ["@authority"] },
	},
};

/** Server config that disables replayable globally. */
const NON_REPLAYABLE_CONFIG: ServerConfig = {
	max_validity_sec: 300,
	route_policies: {
		default: { replayable: false },
	},
};

function createMockSigner(): EthHttpSigner {
	return {
		address: defaultAddress,
		chainId: defaultChainId,
		signMessage: vi.fn(async () => "0xdeadbeef" as `0x${string}`),
	};
}

function createMockStore(): Erc8128SignatureStore & {
	_map: Map<string, CachedSignature[]>;
} {
	const map = new Map<string, CachedSignature[]>();
	return {
		get: vi.fn((keyId: string) => map.get(keyId) ?? null),
		set: vi.fn((keyId: string, entries: CachedSignature[]) => {
			map.set(keyId, entries);
		}),
		delete: vi.fn((keyId: string) => {
			map.delete(keyId);
		}),
		_map: map,
	};
}

const DEFAULT_COMPONENTS = ["@method", "@target-uri", "@authority"];

function mockSignRequestFn(opts?: {
	expires?: number;
	created?: number;
	components?: string[];
}) {
	const created = opts?.created ?? Math.floor(Date.now() / 1000);
	const expires = opts?.expires ?? created + 300;
	const components = opts?.components ?? DEFAULT_COMPONENTS;
	const componentStr = components.map((c) => `"${c}"`).join(" ");

	return vi.fn(async (req: Request) => {
		const headers = new Headers(req.headers);
		headers.set("signature", "sig1=:bW9jaw==:");
		headers.set(
			"signature-input",
			`sig1=(${componentStr});created=${created};expires=${expires};keyid="${defaultKeyId}"`,
		);
		return new Request(req.url, { method: req.method, headers });
	});
}

function setupMockSignerClient(signFn?: ReturnType<typeof mockSignRequestFn>) {
	const fn = signFn ?? mockSignRequestFn();
	vi.mocked(createSignerClient).mockReturnValue({
		signRequest: fn,
		signedFetch: vi.fn(),
		fetch: vi.fn(),
		setServerConfig: vi.fn(),
	} as unknown as SignerClient);
	return fn;
}

async function setupPluginWithConfig(opts: {
	signer?: EthHttpSigner;
	storage?: Erc8128SignatureStore | false;
	config?: ServerConfig;
	signFn?: ReturnType<typeof mockSignRequestFn>;
	expiryMarginSec?: number;
	preferReplayable?: boolean;
	components?: string[];
	ttlSeconds?: number;
	label?: string;
	contentDigest?: "auto" | "recompute" | "require" | "off";
}) {
	const signFn = setupMockSignerClient(opts.signFn);
	const plugin = erc8128Client({
		signer: opts.signer ?? createMockSigner(),
		storage: opts.storage === undefined ? false : opts.storage,
		expiryMarginSec: opts.expiryMarginSec,
		preferReplayable: opts.preferReplayable,
		components: opts.components,
		ttlSeconds: opts.ttlSeconds,
		label: opts.label,
		contentDigest: opts.contentDigest,
	});

	if (opts.config && plugin.getActions) {
		const mockFetch = vi.fn().mockResolvedValue({ data: opts.config });
		plugin.getActions(mockFetch as never, {} as never, undefined);
		await vi.waitFor(() => {
			if (!mockFetch.mock.results[0]?.value) throw new Error("pending");
		});
		// flush microtask to let the .then() in getActions run
		await new Promise((r) => setTimeout(r, 0));
	}

	return { plugin, signFn };
}

function getInitHook(plugin: ReturnType<typeof erc8128Client>) {
	return plugin.fetchPlugins![0]!.init! as (
		url: string,
		fetchOptions?: Record<string, unknown>,
	) => Promise<{ url: string; options?: Record<string, unknown> }>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("erc8128Client", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("returns type-only plugin when no signer is provided", () => {
		const plugin = erc8128Client();
		expect(plugin.id).toBe("erc8128");
		expect(plugin.fetchPlugins).toBeUndefined();
		expect(plugin.getActions).toBeUndefined();
	});

	it("returns plugin with fetchPlugins when signer is provided", () => {
		setupMockSignerClient();
		const plugin = erc8128Client({ signer: createMockSigner() });
		expect(plugin.id).toBe("erc8128");
		expect(plugin.fetchPlugins).toHaveLength(1);
		expect(plugin.getActions).toBeDefined();
	});

	describe("init hook — signing", () => {
		it("skips signing for /.well-known/erc8128", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({});
			const init = getInitHook(plugin);

			await init("/.well-known/erc8128", {
				baseURL: BASE_URL,
				method: "GET",
			});

			expect(signFn).not.toHaveBeenCalled();
		});

		it("signs requests and injects Signature + Signature-Input", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({});
			const init = getInitHook(plugin);

			const result = await init("/session", {
				baseURL: BASE_URL,
				method: "GET",
			});

			expect(signFn).toHaveBeenCalledOnce();
			const headers = result.options?.headers as Headers;
			expect(headers.get("signature")).toBeTruthy();
			expect(headers.get("signature-input")).toContain("expires=");
		});

		it("uses request-bound binding when server config is unknown", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});

		it("preserves original headers when adding signature", async () => {
			const { plugin } = await setupPluginWithConfig({});
			const init = getInitHook(plugin);

			const result = await init("/session", {
				baseURL: BASE_URL,
				method: "GET",
				headers: { "x-custom": "value" },
			});

			const headers = result.options?.headers as Headers;
			expect(headers.get("x-custom")).toBe("value");
			expect(headers.get("signature")).toBeTruthy();
		});

		it("skips signing when signer function returns null", async () => {
			const signFn = setupMockSignerClient();
			const plugin = erc8128Client({
				signer: () => null,
				storage: false,
			});
			const init = getInitHook(plugin);

			const result = await init("/session", {
				baseURL: BASE_URL,
				method: "GET",
			});

			expect(signFn).not.toHaveBeenCalled();
			expect(result.url).toBe("/session");
		});

		it("gracefully handles unparseable URL", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({});
			const init = getInitHook(plugin);

			// No baseURL and relative path → invalid URL
			const result = await init("/session", {});

			expect(signFn).not.toHaveBeenCalled();
			expect(result.url).toBe("/session");
		});
	});

	describe("init hook — replayable routing", () => {
		it("uses class-bound binding for replayable routes", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "class-bound" }),
			);
		});

		it("uses request-bound when server disables replayable", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				config: NON_REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});

		it("respects per-route replayable: false override", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				config: {
					max_validity_sec: 300,
					route_policies: {
						default: {
							replayable: true,
							classBoundPolicies: ["@authority"],
						},
						"POST /api/auth/erc8128/invalidate": { replayable: false },
					},
				},
			});
			const init = getInitHook(plugin);

			await init("/erc8128/invalidate", {
				baseURL: BASE_URL,
				method: "POST",
			});

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});

		it("matches wildcard route policies", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				config: {
					max_validity_sec: 300,
					route_policies: {
						default: {
							replayable: true,
							classBoundPolicies: ["@authority"],
						},
						"GET /api/auth/admin/*": { replayable: false },
					},
				},
			});
			const init = getInitHook(plugin);

			await init("/admin/users", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});
	});

	describe("signature caching", () => {
		it("caches replayable signature as array in store", async () => {
			const store = createMockStore();
			const { plugin } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(store.set).toHaveBeenCalledOnce();
			const [key, entries] = (store.set as ReturnType<typeof vi.fn>).mock
				.calls[0]!;
			expect(key).toBe(defaultKeyId);
			expect(entries).toHaveLength(1);
			expect(entries[0].signature).toBeTruthy();
			expect(entries[0].signatureInput).toBeTruthy();
			expect(entries[0].expires).toBeTypeOf("number");
			expect(entries[0].components).toEqual(DEFAULT_COMPONENTS);
		});

		it("does not cache request-bound signatures", async () => {
			const store = createMockStore();
			const { plugin } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: NON_REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(store.set).not.toHaveBeenCalled();
		});

		it("uses cached signature on second request (skips signRequest)", async () => {
			const store = createMockStore();
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			// First request — signs and caches
			await init("/session", { baseURL: BASE_URL, method: "GET" });
			expect(signFn).toHaveBeenCalledOnce();

			// Second request — uses cache
			signFn.mockClear();
			const result = await init("/other", {
				baseURL: BASE_URL,
				method: "GET",
			});

			expect(signFn).not.toHaveBeenCalled();
			const headers = result.options?.headers as Headers;
			expect(headers.get("signature")).toBe("sig1=:bW9jaw==:");
		});

		it("prunes expired entries and signs fresh", async () => {
			const store = createMockStore();
			const expiredCreated = Math.floor(Date.now() / 1000) - 600;
			const expiredExpires = expiredCreated + 300; // expired 300s ago

			// Pre-populate cache with expired signature
			store._map.set(defaultKeyId, [
				{
					signature: "old-sig",
					signatureInput: "old-input",
					expires: expiredExpires,
					components: DEFAULT_COMPONENTS,
				},
			]);

			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			// All entries expired → delete then sign fresh and save new array
			expect(store.delete).toHaveBeenCalledWith(defaultKeyId);
			expect(signFn).toHaveBeenCalledOnce();
			// New entry was cached
			const saved = store._map.get(defaultKeyId);
			expect(saved).toHaveLength(1);
			expect(saved![0]!.signature).toBe("sig1=:bW9jaw==:");
		});

		it("considers expiryMarginSec when checking cache", async () => {
			const store = createMockStore();
			const now = Math.floor(Date.now() / 1000);

			// Signature expires in 5 seconds — within a 10s margin
			store._map.set(defaultKeyId, [
				{
					signature: "almost-expired-sig",
					signatureInput: "almost-expired-input",
					expires: now + 5,
					components: DEFAULT_COMPONENTS,
				},
			]);

			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: REPLAYABLE_CONFIG,
				expiryMarginSec: 10,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			// Within margin — should sign fresh
			expect(signFn).toHaveBeenCalledOnce();
		});
	});

	describe("class-bound component filtering", () => {
		it("uses cached signature when components satisfy route policy", async () => {
			const store = createMockStore();
			const now = Math.floor(Date.now() / 1000);

			store._map.set(defaultKeyId, [
				{
					signature: "cached-sig",
					signatureInput: `sig1=("@method" "@authority");created=${now};expires=${now + 300}`,
					expires: now + 300,
					components: ["@method", "@authority"],
				},
			]);

			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: {
					max_validity_sec: 300,
					route_policies: {
						"GET /api/auth/session": {
							replayable: true,
							classBoundPolicies: ["@method", "@authority"],
						},
					},
				},
			});
			const init = getInitHook(plugin);

			const result = await init("/session", {
				baseURL: BASE_URL,
				method: "GET",
			});

			// Cache hit — no fresh sign
			expect(signFn).not.toHaveBeenCalled();
			const headers = result.options?.headers as Headers;
			expect(headers.get("signature")).toBe("cached-sig");
		});

		it("appends fresh sig when no cached entry matches route components", async () => {
			const store = createMockStore();
			const now = Math.floor(Date.now() / 1000);

			// Cached signature covers @method + @authority only
			store._map.set(defaultKeyId, [
				{
					signature: "cached-sig",
					signatureInput: `sig1=("@method" "@authority");created=${now};expires=${now + 300}`,
					expires: now + 300,
					components: ["@method", "@authority"],
				},
			]);

			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: {
					max_validity_sec: 300,
					route_policies: {
						// Route requires @method + @authority + @target-uri
						"GET /api/auth/session": {
							replayable: true,
							classBoundPolicies: ["@method", "@authority", "@target-uri"],
						},
					},
				},
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			// Signs fresh and appends to the existing entries
			expect(signFn).toHaveBeenCalledOnce();
			expect(store.delete).not.toHaveBeenCalled();
			const saved = store._map.get(defaultKeyId)!;
			expect(saved).toHaveLength(2);
			expect(saved[0]!.signature).toBe("cached-sig"); // original preserved
			expect(saved[1]!.signature).toBe("sig1=:bW9jaw==:"); // fresh appended
		});

		it("selects correct entry from multiple cached signatures", async () => {
			const store = createMockStore();
			const now = Math.floor(Date.now() / 1000);

			store._map.set(defaultKeyId, [
				{
					signature: "sig-method-only",
					signatureInput: `sig1=("@method");created=${now};expires=${now + 300}`,
					expires: now + 300,
					components: ["@method"],
				},
				{
					signature: "sig-method-authority",
					signatureInput: `sig1=("@method" "@authority");created=${now};expires=${now + 300}`,
					expires: now + 300,
					components: ["@method", "@authority"],
				},
			]);

			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: {
					max_validity_sec: 300,
					route_policies: {
						"GET /api/auth/session": {
							replayable: true,
							classBoundPolicies: ["@method", "@authority"],
						},
					},
				},
			});
			const init = getInitHook(plugin);

			const result = await init("/session", {
				baseURL: BASE_URL,
				method: "GET",
			});

			expect(signFn).not.toHaveBeenCalled();
			const headers = result.options?.headers as Headers;
			// Second entry matches — first doesn't cover @authority
			expect(headers.get("signature")).toBe("sig-method-authority");
		});

		it("passes components from route policy to signRequest", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				config: {
					max_validity_sec: 300,
					route_policies: {
						"GET /api/auth/session": {
							replayable: true,
							classBoundPolicies: ["@method", "@authority"],
						},
					},
				},
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({
					binding: "class-bound",
					components: expect.arrayContaining(["@method", "@authority"]),
				}),
			);
		});

		it("accepts cached sig when it satisfies default classBoundPolicies", async () => {
			const store = createMockStore();
			const now = Math.floor(Date.now() / 1000);

			// Cached sig covers @authority — matches REPLAYABLE_CONFIG default
			store._map.set(defaultKeyId, [
				{
					signature: "cached-sig",
					signatureInput: `sig1=("@authority");created=${now};expires=${now + 300}`,
					expires: now + 300,
					components: ["@authority"],
				},
			]);

			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).not.toHaveBeenCalled();
		});

		it("matches when cached sig satisfies one of multiple classBoundPolicies", async () => {
			const store = createMockStore();
			const now = Math.floor(Date.now() / 1000);

			// Cached covers @method + @authority
			store._map.set(defaultKeyId, [
				{
					signature: "cached-sig",
					signatureInput: `sig1=("@method" "@authority");created=${now};expires=${now + 300}`,
					expires: now + 300,
					components: ["@method", "@authority"],
				},
			]);

			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				storage: store,
				config: {
					max_validity_sec: 300,
					route_policies: {
						"GET /api/auth/session": {
							replayable: true,
							// list-of-lists: first requires @method+@target-uri,
							// second requires @method+@authority — cached satisfies second
							classBoundPolicies: [
								["@method", "@target-uri"],
								["@method", "@authority"],
							] as string[] | string[][],
						},
					},
				},
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).not.toHaveBeenCalled();
		});
	});

	describe("getActions", () => {
		it("fetches server config from /.well-known/erc8128", async () => {
			setupMockSignerClient();
			const plugin = erc8128Client({ signer: createMockSigner() });

			const mockFetch = vi.fn().mockResolvedValue({
				data: {
					max_validity_sec: 300,
				},
			});

			plugin.getActions!(mockFetch as never, {} as never, undefined);
			await new Promise((r) => setTimeout(r, 0));

			expect(mockFetch).toHaveBeenCalledWith("/.well-known/erc8128", {
				method: "GET",
			});
		});

		it("clearSignatureCache removes all cached signatures", async () => {
			const store = createMockStore();
			store._map.set(defaultKeyId, [
				{
					signature: "cached",
					signatureInput: "input",
					expires: 0,
					components: [],
				},
			]);

			setupMockSignerClient();
			const plugin = erc8128Client({
				signer: createMockSigner(),
				storage: store,
			});

			const actions = plugin.getActions!(
				vi.fn().mockResolvedValue({}) as never,
				{} as never,
				undefined,
			);

			await actions.clearSignatureCache();

			expect(store.delete).toHaveBeenCalledWith(defaultKeyId);
		});
	});

	describe("client signing posture", () => {
		it("defaults to request-bound even when server allows replayable", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				// preferReplayable defaults to false
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});

		it("uses request-bound when preferReplayable is true but components is undefined", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				// components not set → undefined → request-bound
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});

		it("does not cache when preferReplayable is true but components is undefined", async () => {
			const store = createMockStore();
			const { plugin } = await setupPluginWithConfig({
				preferReplayable: true,
				storage: store,
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(store.set).not.toHaveBeenCalled();
		});

		it("uses class-bound when preferReplayable is true and components is []", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				config: REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "class-bound" }),
			);
		});

		it("merges client components with route classBoundPolicies", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: ["@method"],
				config: {
					max_validity_sec: 300,
					route_policies: {
						"GET /api/auth/session": {
							replayable: true,
							classBoundPolicies: ["@authority", "@target-uri"],
						},
					},
				},
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({
					binding: "class-bound",
					components: expect.arrayContaining([
						"@method",
						"@authority",
						"@target-uri",
					]),
				}),
			);
		});

		it("falls back to request-bound when server disables replayable", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				preferReplayable: true,
				components: [],
				config: NON_REPLAYABLE_CONFIG,
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});

		it("uses request-bound when server config has not loaded yet", async () => {
			const signFn = setupMockSignerClient();
			const plugin = erc8128Client({
				signer: createMockSigner(),
				storage: false,
				preferReplayable: true,
				components: [],
			});
			// Do NOT call getActions → serverConfig stays null
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ binding: "request-bound" }),
			);
		});

		it("forwards ttlSeconds and label to signRequest", async () => {
			const { plugin, signFn } = await setupPluginWithConfig({
				ttlSeconds: 120,
				label: "my-label",
			});
			const init = getInitHook(plugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });

			expect(signFn).toHaveBeenCalledWith(
				expect.any(Request),
				expect.objectContaining({ ttlSeconds: 120, label: "my-label" }),
			);
		});
	});

	describe("signer identity change", () => {
		it("recreates signer client when address changes", async () => {
			let currentSigner = createMockSigner();
			setupMockSignerClient();
			const dynamicPlugin = erc8128Client({
				signer: () => currentSigner,
				storage: false,
			});
			const init = getInitHook(dynamicPlugin);

			await init("/session", { baseURL: BASE_URL, method: "GET" });
			expect(createSignerClient).toHaveBeenCalledTimes(1);

			// Change signer identity
			currentSigner = {
				...currentSigner,
				address: "0x0000000000000000000000000000000000001234",
			};

			await init("/session", { baseURL: BASE_URL, method: "GET" });
			expect(createSignerClient).toHaveBeenCalledTimes(2);
		});
	});
});
