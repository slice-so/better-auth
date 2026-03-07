import type {
	BetterAuthClientOptions,
	BetterAuthClientPlugin,
	ClientStore,
} from "@better-auth/core";
import type { BetterFetch, BetterFetchOption } from "@better-fetch/fetch";
import type {
	EthHttpSigner,
	ReplayMode,
	RoutePolicy,
	ServerConfig,
	SignerClient,
	SignerClientOptions,
} from "@slicekit/erc8128";
import {
	createSignerClient,
	formatKeyId,
	matchRoutePolicy,
	resolvePosture,
} from "@slicekit/erc8128";
import type { erc8128 } from ".";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CachedSignature {
	signature: string;
	signatureInput: string;
	expires: number;
	binding?: "request-bound" | "class-bound";
	requestKey?: string;
	/** Derived-component identifiers covered by this signature. */
	components: string[];
}

/**
 * Async-capable signature store for caching replayable signatures.
 * Implement this for backend/Node.js environments that don't have
 * `localStorage` (e.g. Redis, database, in-memory Map).
 *
 * Each keyId maps to an **array** of cached signatures. Replayable
 * request-bound signatures are reused only for the exact same request
 * fingerprint, while class-bound signatures can satisfy multiple routes
 * when their covered components are sufficient.
 */
export interface Erc8128SignatureStore {
	/** Retrieve all cached signatures for a keyId, or `null` if none. */
	get(
		keyId: string,
	): CachedSignature[] | null | Promise<CachedSignature[] | null>;
	/** Replace the full set of cached signatures for a keyId. */
	set(keyId: string, entries: CachedSignature[]): void | Promise<void>;
	/** Remove all cached entries for a keyId. */
	delete(keyId: string): void | Promise<void>;
}

/**
 * Fields from `ClientOptions` that the plugin manages internally.
 * - `serverConfigs` — fetched from `/.well-known/erc8128` by the plugin.
 * - `fetch` — not needed (Better Auth handles fetching).
 */
type PluginManagedOptions = "serverConfigs" | "fetch";

export interface Erc8128ClientOptions
	extends Omit<SignerClientOptions, PluginManagedOptions> {
	/**
	 * ERC-8128 signer identity. Can be a static object or a function
	 * returning one (for lazy/dynamic wallet connections).
	 * When the function returns `null`/`undefined`, requests are not signed.
	 */
	signer?: EthHttpSigner | (() => EthHttpSigner | null | undefined);
	/**
	 * Key prefix used by the built-in `localStorage` adapter.
	 * Ignored when a custom `Erc8128SignatureStore` is provided.
	 * @default "erc8128"
	 */
	storagePrefix?: string;
	/**
	 * Seconds before actual expiry to consider a cached signature stale.
	 * Prevents races with server-side expiry checks.
	 * @default 10
	 */
	expiryMarginSec?: number;
	/**
	 * Where to cache replayable signatures.
	 *
	 * - `"localStorage"` — use the browser `localStorage` (default in browsers).
	 * - An `Erc8128SignatureStore` object — custom async-capable store
	 *   (Redis, database, in-memory Map, etc.) for backend use.
	 * - `false` — disable caching entirely.
	 *
	 * When omitted, `localStorage` is used if available, otherwise no caching.
	 */
	storage?: "localStorage" | Erc8128SignatureStore | false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SKIP_PATHS = ["/.well-known/erc8128"];
/** Seconds before actual expiry to consider a cached signature stale. */
const DEFAULT_EXPIRY_MARGIN_SEC = 10;

function parseExpiresFromSignatureInput(signatureInput: string): number | null {
	const match = signatureInput.match(/expires=(\d+)/);
	return match ? Number(match[1]) : null;
}

/** Parse the component list from a Signature-Input value, e.g. `("@authority" "x-hdr")`. */
function parseComponentsFromSignatureInput(signatureInput: string): string[] {
	const match = signatureInput.match(/=\(([^)]*)\)/);
	if (!match) return [];
	const inner = match[1]!.trim();
	if (!inner) return [];
	return [...inner.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
}

function isBodyInit(body: unknown): body is BodyInit {
	return (
		typeof body === "string" ||
		body instanceof URLSearchParams ||
		(typeof FormData !== "undefined" && body instanceof FormData) ||
		(typeof Blob !== "undefined" && body instanceof Blob) ||
		body instanceof ArrayBuffer ||
		ArrayBuffer.isView(body) ||
		(typeof ReadableStream !== "undefined" && body instanceof ReadableStream)
	);
}

function resolveRequestBody(body: unknown): BodyInit | null | undefined {
	if (body === undefined || body === null) {
		return body;
	}
	if (isBodyInit(body)) {
		return body;
	}
	if (typeof body === "object") {
		return JSON.stringify(body);
	}
	return String(body);
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
		"",
	);
}

async function createRequestFingerprint(request: Request): Promise<string> {
	const headerEntries = Array.from(request.headers.entries())
		.filter(
			([name]) =>
				name.toLowerCase() !== "signature" &&
				name.toLowerCase() !== "signature-input",
		)
		.sort(([left], [right]) => left.localeCompare(right));

	const bodyBytes =
		request.method === "GET" || request.method === "HEAD"
			? ""
			: bytesToHex(new Uint8Array(await request.clone().arrayBuffer()));

	return JSON.stringify({
		method: request.method,
		url: request.url,
		headers: headerEntries,
		body: bodyBytes,
	});
}

function matchesCachedSignature(
	entry: CachedSignature,
	routePolicy: RoutePolicy | undefined,
	requestKey: string,
): boolean {
	if (entry.binding === "request-bound") {
		return entry.requestKey === requestKey;
	}

	return matchesClassBoundPolicy(entry.components, routePolicy);
}

/**
 * Check whether a cached signature's components satisfy at least one of
 * the route's classBoundPolicies. Returns `true` when no policy is set.
 */
function matchesClassBoundPolicy(
	signedComponents: string[],
	policy?: RoutePolicy,
): boolean {
	if (!policy?.classBoundPolicies || policy.classBoundPolicies.length === 0)
		return true;

	const policies: string[][] = Array.isArray(policy.classBoundPolicies[0])
		? (policy.classBoundPolicies as string[][])
		: [policy.classBoundPolicies as string[]];

	return policies.some((required) =>
		required.every((comp) => signedComponents.includes(comp)),
	);
}

function buildFullUrl(base: string, path: string): string {
	if (path.startsWith("http")) return path;
	const b = base.replace(/\/$/, "");
	const p = path.startsWith("/") ? path : `/${path}`;
	return `${b}${p}`;
}

type RequestInitWithDuplex = RequestInit & {
	duplex?: "half" | "full";
};

function createLocalStorageAdapter(prefix: string): Erc8128SignatureStore {
	return {
		get(keyId) {
			try {
				const raw = localStorage.getItem(`${prefix}:sig:${keyId}`);
				if (!raw) return null;
				const parsed = JSON.parse(raw);
				// Migrate single-entry format → array
				return Array.isArray(parsed) ? parsed : [parsed];
			} catch {
				return null;
			}
		},
		set(keyId, entries) {
			try {
				localStorage.setItem(`${prefix}:sig:${keyId}`, JSON.stringify(entries));
			} catch {
				/* quota exceeded or restricted context */
			}
		},
		delete(keyId) {
			try {
				localStorage.removeItem(`${prefix}:sig:${keyId}`);
			} catch {
				/* ignore */
			}
		},
	};
}

function resolveStore(
	options: Erc8128ClientOptions,
): Erc8128SignatureStore | null {
	const raw = options.storage;
	if (raw === false) return null;
	if (typeof raw === "object") return raw;
	// raw === "localStorage" or undefined → auto-detect
	if (typeof localStorage !== "undefined") {
		return createLocalStorageAdapter(options.storagePrefix ?? "erc8128");
	}
	return null;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const erc8128Client = (options?: Erc8128ClientOptions) => {
	if (!options?.signer) {
		return {
			id: "erc8128",
			$InferServerPlugin: {} as ReturnType<typeof erc8128>,
		} satisfies BetterAuthClientPlugin;
	}

	const {
		signer: _signer,
		storagePrefix: _storagePrefix,
		expiryMarginSec,
		storage: _storage,
		preferReplayable = false,
		...forwardedSignOptions
	} = options;

	const store = resolveStore(options);
	const margin = expiryMarginSec ?? DEFAULT_EXPIRY_MARGIN_SEC;
	const replay: ReplayMode = preferReplayable ? "replayable" : "non-replayable";

	let serverConfig: ServerConfig | null = null;
	let signerClient: SignerClient | null = null;
	let signerKey = "";

	// -- signer resolution ---------------------------------------------------

	function resolveSigner(): EthHttpSigner | null {
		if (typeof options!.signer === "function") {
			return options!.signer() ?? null;
		}
		return options!.signer ?? null;
	}

	function getClient(signer: EthHttpSigner): SignerClient {
		const key = `${signer.chainId}:${signer.address.toLowerCase()}`;
		if (signerClient && signerKey === key) return signerClient;
		signerClient = createSignerClient(signer, {
			preferReplayable,
			...forwardedSignOptions,
		});
		signerKey = key;
		return signerClient;
	}

	function getKeyId(signer: EthHttpSigner): string {
		return formatKeyId(signer.chainId, signer.address);
	}

	// -- plugin return -------------------------------------------------------

	return {
		id: "erc8128",
		$InferServerPlugin: {} as ReturnType<typeof erc8128>,
		getActions: (
			$fetch: BetterFetch,
			_$store: ClientStore,
			_clientOptions: BetterAuthClientOptions | undefined,
		) => {
			$fetch("/.well-known/erc8128", { method: "GET" })
				.then((result) => {
					// BetterFetch wraps responses in { data, error }
					const response = result as { data?: Record<string, unknown> | null };
					const payload = response.data;
					if (payload && typeof payload.max_validity_sec === "number") {
						serverConfig = payload as ServerConfig;
					}
				})
				.catch(() => {});

			return {
				clearSignatureCache: async () => {
					const signer = resolveSigner();
					if (signer && store) await store.delete(getKeyId(signer));
				},
			};
		},
		fetchPlugins: [
			{
				id: "erc8128-signer",
				name: "erc8128-signer",
				init: async (url: string, fetchOptions?: BetterFetchOption) => {
					const signer = resolveSigner();
					if (!signer) return { url, options: fetchOptions };

					const baseURL: string = (fetchOptions?.baseURL as string) || "";
					const fullUrl = buildFullUrl(baseURL, url);

					if (SKIP_PATHS.some((p) => fullUrl.endsWith(p))) {
						return { url, options: fetchOptions };
					}

					let parsedUrl: URL;
					try {
						parsedUrl = new URL(fullUrl);
					} catch {
						return { url, options: fetchOptions };
					}

					const method = (
						(fetchOptions?.method as string) || "GET"
					).toUpperCase();
					const client = getClient(signer);
					const keyId = getKeyId(signer);
					const requestInit: RequestInitWithDuplex = {
						method,
						headers: (fetchOptions?.headers as HeadersInit) || {},
						body: resolveRequestBody(fetchOptions?.body),
						duplex: fetchOptions?.duplex,
					};
					const tempReq = new Request(fullUrl, requestInit);

					// Apply server config to the client so it can resolve posture
					if (serverConfig) {
						client.setServerConfig(parsedUrl.origin, serverConfig);
					}

					// Resolve posture for cache decision only — the client handles
					// posture resolution internally when signing.
					const posture = resolvePosture(
						method,
						parsedUrl.pathname,
						serverConfig,
						{ ...forwardedSignOptions, replay },
					);
					const useCache = posture.replay === "replayable";
					const requestKey = useCache
						? await createRequestFingerprint(tempReq)
						: "";

					// Resolve route policy for cache matching (supports
					// list-of-lists classBoundPolicies alternatives)
					const routePolicy =
						useCache && serverConfig?.route_policies
							? matchRoutePolicy(
									method,
									parsedUrl.pathname,
									serverConfig.route_policies,
								)
							: undefined;

					// Try cache for replayable routes. Request-bound entries are
					// reusable only for the same request fingerprint.
					const now = Math.floor(Date.now() / 1000);
					let validEntries: CachedSignature[] | null = null;

					if (useCache && store) {
						const all = await store.get(keyId);
						if (all && all.length > 0) {
							// Drop expired entries
							validEntries = all.filter((e) => e.expires - margin > now);
							if (validEntries.length < all.length) {
								// Persist the pruned list (or delete if empty)
								if (validEntries.length > 0) {
									await store.set(keyId, validEntries);
								} else {
									await store.delete(keyId);
									validEntries = null;
								}
							}

							// Find a reusable entry for this request.
							const match = validEntries?.find((e) =>
								matchesCachedSignature(e, routePolicy, requestKey),
							);
							if (match) {
								const headers = new Headers(
									(fetchOptions?.headers as HeadersInit) || {},
								);
								headers.set("signature", match.signature);
								headers.set("signature-input", match.signatureInput);
								return { url, options: { ...fetchOptions, headers } };
							}
						}
					}

					const signedReq = await client.signRequest(tempReq);

					const sig = signedReq.headers.get("signature");
					const sigInput = signedReq.headers.get("signature-input");
					if (!sig || !sigInput) return { url, options: fetchOptions };

					const headers = new Headers(
						(fetchOptions?.headers as HeadersInit) || {},
					);
					headers.set("signature", sig);
					headers.set("signature-input", sigInput);

					// Cache replayable signatures. Request-bound entries carry an
					// exact request fingerprint so they are only reused when safe.
					if (useCache && store) {
						const expires = parseExpiresFromSignatureInput(sigInput);
						if (expires) {
							const entry: CachedSignature = {
								signature: sig,
								signatureInput: sigInput,
								expires,
								binding: posture.binding,
								requestKey:
									posture.binding === "request-bound" ? requestKey : undefined,
								components: parseComponentsFromSignatureInput(sigInput),
							};
							const updated = [...(validEntries ?? []), entry];
							await store.set(keyId, updated);
						}
					}

					return { url, options: { ...fetchOptions, headers } };
				},
			},
		],
	} satisfies BetterAuthClientPlugin;
};
