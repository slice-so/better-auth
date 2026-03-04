import type { BetterAuthClientPlugin } from "@better-auth/core";
import type {
	Client as Erc8128SignerClient,
	ClientOptions as Erc8128SignerClientOptions,
	EthHttpSigner,
	RoutePolicy,
	ServerConfig,
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
	/** Derived-component identifiers covered by this signature. */
	components: string[];
}

/**
 * Async-capable signature store for caching replayable signatures.
 * Implement this for backend/Node.js environments that don't have
 * `localStorage` (e.g. Redis, database, in-memory Map).
 *
 * Each keyId maps to an **array** of cached signatures — different routes
 * may require different class-bound components, so multiple valid entries
 * can coexist until they expire.
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
	extends Omit<Erc8128SignerClientOptions, PluginManagedOptions> {
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
		minComponents,
		...forwardedSignOptions
	} = options;

	const store = resolveStore(options);
	const margin = expiryMarginSec ?? 10;

	let serverConfig: ServerConfig | null = null;
	let signerClient: Erc8128SignerClient | null = null;
	let signerKey = "";

	// -- signer resolution ---------------------------------------------------

	function resolveSigner(): EthHttpSigner | null {
		if (typeof options!.signer === "function") {
			return options!.signer() ?? null;
		}
		return options!.signer ?? null;
	}

	function getClient(signer: EthHttpSigner): Erc8128SignerClient {
		const key = `${signer.chainId}:${signer.address.toLowerCase()}`;
		if (signerClient && signerKey === key) return signerClient;
		signerClient = createSignerClient(signer);
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
			$fetch: (...args: any[]) => Promise<any>,
			_$store: any,
			_clientOptions: any,
		) => {
			$fetch("/.well-known/erc8128", { method: "GET" })
				.then((result: any) => {
					const data = result?.data ?? result;
					if (data?.replay_protection) {
						serverConfig = data;
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
				init: async (url: string, fetchOptions?: Record<string, any>) => {
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

					// -- determine signing posture via library ----------------------
					// When server config hasn't loaded yet, use safest posture.
					const posture = serverConfig
						? resolvePosture(
								method,
								parsedUrl.pathname,
								preferReplayable,
								minComponents,
								serverConfig,
							)
						: {
								binding: "request-bound" as const,
								replay: "non-replayable" as const,
								components: undefined,
							};
					const useCache =
						posture.binding === "class-bound" &&
						posture.replay === "replayable";

					// Resolve route policy for cache matching
					const routePolicy =
						useCache && serverConfig?.route_policies
							? matchRoutePolicy(
									method,
									parsedUrl.pathname,
									serverConfig.route_policies,
								)
							: undefined;

					// Try cache for class-bound replayable routes
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

							// Find an entry whose components satisfy the route
							const match = validEntries?.find((e) =>
								matchesClassBoundPolicy(e.components, routePolicy),
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

					// Build a temporary Request for signing
					const tempReq = new Request(fullUrl, {
						method,
						headers: (fetchOptions?.headers as HeadersInit) || {},
					});

					const signedReq = await client.signRequest(tempReq, {
						...forwardedSignOptions,
						binding: posture.binding,
						replay: posture.replay,
						...(posture.components ? { components: posture.components } : {}),
					});

					const sig = signedReq.headers.get("signature");
					const sigInput = signedReq.headers.get("signature-input");
					if (!sig || !sigInput) return { url, options: fetchOptions };

					const headers = new Headers(
						(fetchOptions?.headers as HeadersInit) || {},
					);
					headers.set("signature", sig);
					headers.set("signature-input", sigInput);

					// Cache class-bound replayable signatures
					if (useCache && store) {
						const expires = parseExpiresFromSignatureInput(sigInput);
						if (expires) {
							const entry: CachedSignature = {
								signature: sig,
								signatureInput: sigInput,
								expires,
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
