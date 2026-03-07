import type {
	BetterAuthClientOptions,
	BetterAuthClientPlugin,
	ClientStore,
} from "@better-auth/core";
import type {
	BetterFetch,
	BetterFetchOption,
	FetchEsque,
} from "@better-fetch/fetch";
import type {
	AcceptSignatureSignOptions,
	EthHttpSigner,
	ReplayMode,
	ServerConfig,
	SignerClient,
	SignerClientOptions,
} from "@slicekit/erc8128";
import {
	createSignerClient,
	formatKeyId,
	normalizeAcceptSignatureSignOptions,
	parseAcceptSignatureHeader,
	parseSignatureInputHeader,
	resolvePosture,
	selectAcceptSignatureRetryOptions,
} from "@slicekit/erc8128";
import type { erc8128 } from ".";

export interface CachedSignature {
	signature: string;
	signatureInput: string;
	expires: number;
	signOptions?: AcceptSignatureSignOptions;
	binding?: "request-bound" | "class-bound";
	requestKey?: string;
	components: string[];
}

export interface Erc8128SignatureStore {
	get(
		keyId: string,
	): CachedSignature[] | null | Promise<CachedSignature[] | null>;
	set(keyId: string, entries: CachedSignature[]): void | Promise<void>;
	delete(keyId: string): void | Promise<void>;
}

type PluginManagedOptions = "serverConfigs" | "fetch";

export interface Erc8128ClientOptions
	extends Omit<SignerClientOptions, PluginManagedOptions> {
	signer?: EthHttpSigner | (() => EthHttpSigner | null | undefined);
	storagePrefix?: string;
	expiryMarginSec?: number;
	storage?: "localStorage" | Erc8128SignatureStore | false;
}

const SKIP_PATHS = ["/.well-known/erc8128"];
const DEFAULT_EXPIRY_MARGIN_SEC = 10;
const MAX_ACCEPT_SIGNATURE_RETRIES = 1;

type RequestInitWithDuplex = RequestInit & {
	duplex?: "half" | "full";
};

type SignedRequestResult = {
	headers: Headers;
	signature: string;
	signatureInput: string;
};

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

function arraysEqual(left: string[], right: string[]): boolean {
	return (
		left.length === right.length &&
		left.every((value, index) => value === right[index])
	);
}

function entryToNormalizedSignOptions(
	entry: CachedSignature,
): AcceptSignatureSignOptions {
	if (entry.signOptions) {
		return normalizeAcceptSignatureSignOptions(entry.signOptions);
	}

	return normalizeAcceptSignatureSignOptions({
		binding:
			entry.binding ?? (entry.requestKey ? "request-bound" : "class-bound"),
		replay: "replayable",
		components: entry.components,
	});
}

function matchesCachedSignature(
	entry: CachedSignature,
	targetSignOptions: AcceptSignatureSignOptions,
	requestKey: string,
): boolean {
	const entryOptions = entryToNormalizedSignOptions(entry);

	if (entryOptions.replay !== targetSignOptions.replay) {
		return false;
	}

	if (targetSignOptions.binding === "request-bound") {
		return (
			entryOptions.binding === "request-bound" &&
			entry.requestKey === requestKey
		);
	}

	if (entryOptions.binding !== "class-bound") {
		return false;
	}

	return targetSignOptions.components.every((component) =>
		entryOptions.components.includes(component),
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
				return Array.isArray(parsed) ? parsed : [parsed];
			} catch {
				return null;
			}
		},
		set(keyId, entries) {
			try {
				localStorage.setItem(`${prefix}:sig:${keyId}`, JSON.stringify(entries));
			} catch {}
		},
		delete(keyId) {
			try {
				localStorage.removeItem(`${prefix}:sig:${keyId}`);
			} catch {}
		},
	};
}

function resolveStore(
	options: Erc8128ClientOptions,
): Erc8128SignatureStore | null {
	const raw = options.storage;
	if (raw === false) return null;
	if (typeof raw === "object") return raw;
	if (typeof localStorage !== "undefined") {
		return createLocalStorageAdapter(options.storagePrefix ?? "erc8128");
	}
	return null;
}

export const erc8128Client = (options?: Erc8128ClientOptions) => {
	if (!options?.signer) {
		return {
			id: "erc8128",
			$InferServerPlugin: {} as ReturnType<typeof erc8128>,
		} satisfies BetterAuthClientPlugin;
	}

	const clientOptions = options;

	const {
		signer: _signer,
		storagePrefix: _storagePrefix,
		expiryMarginSec,
		storage: _storage,
		preferReplayable = false,
		...forwardedSignOptions
	} = options;

	const store = resolveStore(clientOptions);
	const margin = expiryMarginSec ?? DEFAULT_EXPIRY_MARGIN_SEC;
	const replay: ReplayMode = preferReplayable ? "replayable" : "non-replayable";

	let serverConfig: ServerConfig | null = null;
	let signerClient: SignerClient | null = null;
	let signerKey = "";

	function resolveSigner(): EthHttpSigner | null {
		if (typeof clientOptions.signer === "function") {
			return clientOptions.signer() ?? null;
		}
		return clientOptions.signer ?? null;
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

	function computeInitialSignOptions(
		request: Request,
	): AcceptSignatureSignOptions {
		const posture = resolvePosture(
			request.method,
			new URL(request.url).pathname,
			serverConfig,
			{ ...forwardedSignOptions, replay },
		);

		return normalizeAcceptSignatureSignOptions({
			binding: posture.binding,
			replay: posture.replay,
			components: posture.components,
		});
	}

	async function signWithOptions(args: {
		request: Request;
		client: SignerClient;
		keyId: string;
		store: Erc8128SignatureStore | null;
		margin: number;
		signOptions: AcceptSignatureSignOptions;
	}): Promise<SignedRequestResult> {
		const { request, client, keyId, store, margin, signOptions } = args;
		const useCache = signOptions.replay === "replayable";
		const requestKey = useCache
			? await createRequestFingerprint(request.clone())
			: "";
		const now = Math.floor(Date.now() / 1000);
		let validEntries: CachedSignature[] | null = null;

		if (useCache && store) {
			const all = await store.get(keyId);
			if (all && all.length > 0) {
				validEntries = all.filter((entry) => entry.expires - margin > now);
				if (validEntries.length < all.length) {
					if (validEntries.length > 0) {
						await store.set(keyId, validEntries);
					} else {
						await store.delete(keyId);
						validEntries = null;
					}
				}

				const match = validEntries?.find((entry) =>
					matchesCachedSignature(entry, signOptions, requestKey),
				);
				if (match) {
					const headers = new Headers(request.headers);
					headers.set("signature", match.signature);
					headers.set("signature-input", match.signatureInput);
					return {
						headers,
						signature: match.signature,
						signatureInput: match.signatureInput,
					};
				}
			}
		}

		const signedReq = await client.signRequest(request.clone(), signOptions);
		const signature = signedReq.headers.get("signature");
		const signatureInput = signedReq.headers.get("signature-input");
		if (!signature || !signatureInput) {
			return {
				headers: new Headers(request.headers),
				signature: "",
				signatureInput: "",
			};
		}

		const parsedInput = parseSignatureInputHeader(signatureInput)[0];
		const headers = new Headers(request.headers);
		headers.set("signature", signature);
		headers.set("signature-input", signatureInput);

		if (useCache && store && parsedInput) {
			const entry: CachedSignature = {
				signature,
				signatureInput,
				expires: parsedInput.params.expires,
				signOptions,
				binding: signOptions.binding,
				requestKey:
					signOptions.binding === "request-bound" ? requestKey : undefined,
				components: parsedInput.components,
			};
			await store.set(keyId, [...(validEntries ?? []), entry]);
		}

		return { headers, signature, signatureInput };
	}

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

					if (SKIP_PATHS.some((path) => fullUrl.endsWith(path))) {
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
					const baseRequest = new Request(fullUrl, requestInit);
					const fetchImpl =
						(fetchOptions?.customFetchImpl as FetchEsque | undefined) ??
						(typeof fetch === "function" ? fetch : undefined);

					if (serverConfig) {
						client.setServerConfig(parsedUrl.origin, serverConfig);
					}

					const initialSignOptions = computeInitialSignOptions(baseRequest);
					const initialSignedRequest = await signWithOptions({
						request: baseRequest,
						client,
						keyId,
						store,
						margin,
						signOptions: initialSignOptions,
					});
					if (
						!initialSignedRequest.signature ||
						!initialSignedRequest.signatureInput
					) {
						return { url, options: fetchOptions };
					}

					const customFetchImpl =
						fetchImpl &&
						(async (input: RequestInfo | URL, init?: RequestInit) => {
							const firstResponse = await fetchImpl(input, init);
							if (firstResponse.status !== 401) {
								return firstResponse;
							}

							const acceptSignature =
								firstResponse.headers.get("accept-signature");
							if (!acceptSignature) {
								return firstResponse;
							}

							try {
								const parsed = parseAcceptSignatureHeader(
									acceptSignature,
									baseRequest.clone(),
								);
								const retrySignOptions = selectAcceptSignatureRetryOptions({
									members: parsed,
									requestShape: baseRequest.clone(),
									attemptedOptions: [initialSignOptions],
								});

								if (!retrySignOptions) {
									return firstResponse;
								}

								const normalizedRetrySignOptions =
									normalizeAcceptSignatureSignOptions(retrySignOptions);
								if (
									normalizedRetrySignOptions.binding ===
										initialSignOptions.binding &&
									normalizedRetrySignOptions.replay ===
										initialSignOptions.replay &&
									arraysEqual(
										normalizedRetrySignOptions.components,
										initialSignOptions.components,
									)
								) {
									return firstResponse;
								}

								let response = firstResponse;
								for (
									let attempt = 0;
									attempt < MAX_ACCEPT_SIGNATURE_RETRIES;
									attempt++
								) {
									const retriedRequest = await signWithOptions({
										request: baseRequest,
										client,
										keyId,
										store,
										margin,
										signOptions: normalizedRetrySignOptions,
									});
									if (
										!retriedRequest.signature ||
										!retriedRequest.signatureInput
									) {
										return firstResponse;
									}

									const retryHeaders = new Headers(baseRequest.headers);
									retryHeaders.set("signature", retriedRequest.signature);
									retryHeaders.set(
										"signature-input",
										retriedRequest.signatureInput,
									);
									const retryRequest = new Request(baseRequest.clone(), {
										headers: retryHeaders,
									});
									response = await fetchImpl(retryRequest.clone());
								}
								return response;
							} catch {
								return firstResponse;
							}
						});

					return {
						url,
						options: {
							...fetchOptions,
							headers: initialSignedRequest.headers,
							...(customFetchImpl ? { customFetchImpl } : {}),
						},
					};
				},
			},
		],
	} satisfies BetterAuthClientPlugin;
};
