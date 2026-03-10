import type {
	AuthContext,
	BetterAuthOptions,
	BetterAuthPlugin,
	GenericEndpointContext,
} from "@better-auth/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@better-auth/core/api";
import type { Session } from "@better-auth/core/db";
import type {
	DiscoveryDocumentConfig,
	RoutePolicy,
	VerifyMessageFn,
	VerifyResult,
} from "@slicekit/erc8128";
import {
	createVerifierClient,
	formatDiscoveryDocument,
} from "@slicekit/erc8128";
import * as z from "zod";
import { APIError } from "../../api";
import { getSessionFromCtx } from "../../api/routes/session";
import { setSessionCookie } from "../../cookies";
import { mergeSchema } from "../../db/schema";
import type { Auth, InferOptionSchema, User } from "../../types";
import { HIDE_METADATA } from "../../utils/hide-metadata";
import { getOrigin } from "../../utils/url";
import {
	createErc8128CleanupScheduler,
	DEFAULT_ERC8128_CLEANUP_THROTTLE_SEC,
} from "./cleanup";
export {
	cleanupExpiredErc8128Storage,
	type CleanupExpiredErc8128StorageOptions,
	type CleanupExpiredErc8128StorageResult,
} from "./cleanup";
import type { InvalidationOps } from "./invalidation-store";
import {
	createDBInvalidationOps,
	createDualInvalidationOps,
	createMemoryInvalidationOps,
	createSecondaryStorageInvalidationOps,
	DEFAULT_INVALIDATION_TTL_SEC,
} from "./invalidation-store";
import {
	createAdapterNonceStore,
	createDualNonceStore,
	createMemoryNonceStore,
	createSecondaryStorageNonceStore,
} from "./nonce-store";
import {
	isPluginEndpoint,
	normalizeRoutePolicyConfig,
	resolveRoutePolicy,
} from "./route-policy";
import type { ERC8128Schema } from "./schema";
import { schema } from "./schema";
import type { ENSLookupArgs, ENSLookupResult, WalletAddress } from "./types";
import {
	getErc8128CacheKey,
	getErc8128SignatureHash,
	parseErc8128KeyId,
} from "./utils";
import type { CacheValue, VerificationCacheOps } from "./verification-cache";
import {
	createVerificationCacheOps,
	DEFAULT_CACHE_SIZE,
} from "./verification-cache";

/**
 * Fallback for invalidation TTL sizing when the user doesn't set `maxValiditySec`.
 * Must match the library's internal default (300s) so invalidation records
 * outlive the signatures they could invalidate.
 */
const DEFAULT_MAX_VALIDITY_SEC = 300;
/** Clock skew tolerance for server-side signature verification. */
const DEFAULT_CLOCK_SKEW_SEC = 30;
/** Only verify one signature per request (the first valid one). */
const MAX_SIGNATURE_VERIFICATIONS = 1;

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		erc8128: {
			creator: typeof erc8128;
		};
	}
}

const ERC8128_VERIFICATION_CONTEXT_KEY = "__erc8128Verification";

export type Erc8128VerifiedRequest = Extract<VerifyResult, { ok: true }>;

type Erc8128ContextCarrier = {
	context?: Record<string, unknown>;
};

export function getErc8128Verification(
	ctx: Erc8128ContextCarrier,
): Erc8128VerifiedRequest | null {
	const value = ctx.context?.[ERC8128_VERIFICATION_CONTEXT_KEY];
	if (!value || typeof value !== "object") {
		return null;
	}
	return value as Erc8128VerifiedRequest;
}

export interface Erc8128Principal {
	session: Session & Record<string, any>;
	user: User & Record<string, any>;
}

export interface Erc8128VerifyRequestOptions {
	policy?: RoutePolicy | undefined;
}

export type Erc8128VerifyRequestResult =
	| {
			ok: true;
			responseHeaders: Headers;
			verification: Erc8128VerifiedRequest;
	  }
	| {
			ok: false;
			response: Response;
			responseHeaders: Headers;
	  };

export interface Erc8128ProtectOptions {
	resolveSession?: (() => Promise<Erc8128Principal | null>) | undefined;
}

export type Erc8128ProtectResult =
	| {
			ok: true;
			authenticated: boolean;
			principal: Erc8128Principal | null;
			protected: boolean;
			responseHeaders: Headers;
			source: "none" | "session" | "signature";
			verification: Erc8128VerifiedRequest | null;
	  }
	| {
			ok: false;
			protected: boolean;
			response: Response;
			responseHeaders: Headers;
	  };

export interface Erc8128ServerApi {
	getConfig: (request?: Request) => Promise<Erc8128ServerConfig>;
	protect: (
		request: Request,
		options?: Erc8128ProtectOptions,
	) => Promise<Erc8128ProtectResult>;
	verifyRequest: (
		request: Request,
		options?: Erc8128VerifyRequestOptions,
	) => Promise<Erc8128VerifyRequestResult>;
}

type Erc8128ServerConfig = ReturnType<typeof formatDiscoveryDocument>;

interface CachedVerifyMessageOps {
	verifyMessage: VerifyMessageFn;
	pending: {
		cacheKey: string;
		address: string;
		signatureHash: string;
	} | null;
	persist(result: Erc8128VerifiedRequest): Promise<void>;
}

type BetterAuthPluginWithServerApi<API extends Record<string, unknown>> =
	BetterAuthPlugin & {
		getServerApi?: (
			ctx: Promise<AuthContext> | AuthContext,
		) => Record<string, unknown>;
		$ServerAPI?: API;
	};

interface ERC8128PluginOptions {
	verifyMessage: VerifyMessageFn;
	sessionExpiresIn?: number | undefined;
	maxValiditySec?: number | undefined;
	clockSkewSec?: number | undefined;
	emailDomainName?: string | undefined;
	anonymous?: boolean | undefined;
	ensLookup?: ((args: ENSLookupArgs) => Promise<ENSLookupResult>) | undefined;
	schema?: InferOptionSchema<typeof schema> | undefined;
	/**
	 * Max entries in the in-memory verification cache. Used by the database
	 * read-through Map and as the sole store when `secondaryStorage` is not
	 * configured. Ignored when `secondaryStorage` is active (TTL-managed).
	 *
	 * @default 10000
	 */
	cacheSize?: number | undefined;
	/**
	 * Per-route policy map keyed by Better Auth endpoint paths relative to the
	 * auth `basePath` (for example `"/get-session"` or `"/erc8128/verify"`).
	 *
	 * The plugin strips Better Auth's mount prefix automatically, so users do
	 * not need to include `/api/auth` (or a custom `basePath`) in keys. Legacy
	 * basePath-prefixed keys are still accepted and normalized internally.
	 */
	routePolicy?: DiscoveryDocumentConfig["routePolicy"] | undefined;
	/**
	 * When `secondaryStorage` is configured, nonces and invalidation records
	 * are stored there by default (with TTL-based auto-cleanup). Set this to
	 * `true` to also persist them to the database, using secondaryStorage as a
	 * fast read-through layer.
	 *
	 * Follows the same pattern as Better Auth's `session.storeSessionInDatabase`.
	 *
	 * Has no effect when `secondaryStorage` is not configured (everything uses
	 * the database).
	 *
	 * @default false
	 */
	storeInDatabase?: boolean | undefined;
	/**
	 * Automatic cleanup strategy for expired ERC-8128 DB rows.
	 *
	 * - `"auto"` — use a best-effort distributed lease in `secondaryStorage`
	 *   when available, otherwise do nothing automatically.
	 * - `"off"` — disable automatic cleanup entirely.
	 *
	 * @default "auto"
	 */
	cleanupStrategy?: "auto" | "off" | undefined;
	/**
	 * Minimum time between automatic ERC-8128 DB cleanup runs.
	 *
	 * @default 300
	 */
	cleanupThrottleSec?: number | undefined;
	/**
	 * How to handle requests that carry both a session cookie and an
	 * ERC-8128 signature.
	 *
	 * - `"session-first"` — session cookie wins; signature verification
	 *   is skipped (default).
	 * - `"signature-first"` — signature wins; session cookie is ignored.
	 * - `"reject-on-mismatch"` — both are verified; if they map to
	 *   different users, return 401.
	 *
	 * @default "session-first"
	 */
	authPrecedence?:
		| "session-first"
		| "signature-first"
		| "reject-on-mismatch"
		| undefined;
}

const invalidateBodySchema = z
	.object({
		notBefore: z.number().int().positive().optional(),
		signature: z.string().startsWith("0x").optional(),
	})
	.optional()
	.refine((data) => !data || !(data.notBefore && data.signature), {
		message: "Provide either notBefore or signature, not both",
	});

function extractKeyIdFromSignatureInput(signatureInput: string): string | null {
	const match = signatureInput.match(/(?:^|;)\s*keyid="([^"]+)"/i);
	return match?.[1] ?? null;
}

const WWW_AUTHENTICATE_HEADER =
	'Signature realm="erc8128", headers="@method @target-uri @authority"';

function toHeaders(headers: Record<string, string>) {
	return new Headers(headers);
}

function jsonErrorResponse(
	status: number,
	body: Record<string, unknown>,
	headers?: Record<string, string>,
) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			...(headers ?? {}),
		},
	});
}

type VerifyFailure = Extract<VerifyResult, { ok: false }>;

function getVerifyFailure(result: VerifyResult): VerifyFailure | null {
	if (!result.ok) {
		return result;
	}
	const nowSec = Math.floor(Date.now() / 1000);
	if (nowSec < result.params.expires) {
		return null;
	}
	return {
		ok: false,
		reason: "expired",
	};
}

function cloneAuthContextForRequest<Options extends BetterAuthOptions>(
	authContext: AuthContext<Options>,
	request?: Request,
) {
	const context = Object.create(
		Object.getPrototypeOf(authContext),
		Object.getOwnPropertyDescriptors(authContext),
	) as AuthContext<Options>;

	if (!context.baseURL && request) {
		context.baseURL = new URL(
			authContext.options.basePath || "/api/auth",
			request.url,
		).toString();
	}

	return context;
}

function withoutSignatureHeaders(request: Request) {
	const headers = new Headers(request.headers);
	headers.delete("signature");
	headers.delete("signature-input");
	return headers;
}

async function requireErc8128Context<Options extends BetterAuthOptions>(
	auth: Auth<Options>,
) {
	const ctx = await auth.$context;
	if (!("erc8128" in ctx) || !ctx.erc8128) {
		throw new Error(
			"[better-auth][erc8128] ERC-8128 plugin is not installed on this auth instance.",
		);
	}
	return ctx.erc8128 as Erc8128ServerApi;
}

export function getErc8128Api<Options extends BetterAuthOptions>(
	auth: Auth<Options>,
): Erc8128ServerApi {
	if ((auth.api as Record<string, unknown>).erc8128) {
		return (auth.api as Record<string, unknown>).erc8128 as Erc8128ServerApi;
	}
	return {
		getConfig: async (request) => {
			const api = await requireErc8128Context(auth);
			return api.getConfig(request);
		},
		protect: async (request, options) => {
			const api = await requireErc8128Context(auth);
			const protectOptions: Erc8128ProtectOptions = {
				resolveSession:
					options?.resolveSession ??
					(async () => {
						const session = await auth.api
							.getSession({
								headers: withoutSignatureHeaders(request),
								request,
							} as any)
							.catch(() => null);

						return session
							? {
									session: session.session as Session & Record<string, any>,
									user: session.user as User & Record<string, any>,
								}
							: null;
					}),
			};
			return api.protect(request, protectOptions);
		},
		verifyRequest: async (request, options) => {
			const api = await requireErc8128Context(auth);
			return api.verifyRequest(request, options);
		},
	};
}

export const erc8128 = (options: ERC8128PluginOptions) => {
	const allowsReplayable = (
		policy: RoutePolicy | RoutePolicy[] | false | undefined,
	): boolean =>
		(Array.isArray(policy) ? policy : [policy]).some(
			(entry) => entry !== false && entry?.replayable === true,
		);

	const replayableEnabled =
		allowsReplayable(options.routePolicy?.default) ||
		(options.routePolicy != null &&
			Object.values(options.routePolicy).some((policy) =>
				allowsReplayable(policy),
			));

	const fallbackCacheMap = new Map<string, CacheValue>();
	const maxCacheSize = options.cacheSize ?? DEFAULT_CACHE_SIZE;
	let warnedNoStorage = false;
	let warnedReplayableNoStorage = false;
	const cleanupThrottleSec =
		options.cleanupThrottleSec ?? DEFAULT_ERC8128_CLEANUP_THROTTLE_SEC;
	const keyInvalidationWindowSec =
		(options.maxValiditySec ?? DEFAULT_MAX_VALIDITY_SEC) +
		(options.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC);

	const warnNoStorage = () => {
		if (warnedNoStorage) return;
		warnedNoStorage = true;
		console.warn(
			"[better-auth][erc8128] No persistent storage available (DB/secondaryStorage). " +
				"Falling back to request-bound middleware verification only for explicit routePolicy routes. " +
				"Endpoints requiring persistence (/erc8128/verify, /erc8128/invalidate) are disabled.",
		);
	};

	const warnReplayableNoStorage = () => {
		if (warnedReplayableNoStorage) return;
		warnedReplayableNoStorage = true;
		console.warn(
			"[better-auth][erc8128] Replayable route policy requested without persistent storage. " +
				"Replayable signatures require DB or secondaryStorage. Protected replayable routes will fail.",
		);
	};

	const ensureStorageMode = async (ctx: GenericEndpointContext) => {
		if (ctx.context.secondaryStorage) {
			return "secondary-storage" as const;
		}
		try {
			await ctx.context.adapter.findMany({
				model: "erc8128Nonce",
				limit: 1,
			});
			return "database" as const;
		} catch {
			warnNoStorage();
			return "none" as const;
		}
	};

	const getCache = (ctx: GenericEndpointContext): VerificationCacheOps => {
		const resolved: "secondary-storage" | "database" = ctx.context
			.secondaryStorage
			? "secondary-storage"
			: "database";
		return createVerificationCacheOps(
			resolved,
			ctx.context.secondaryStorage,
			ctx.context.adapter,
			fallbackCacheMap,
			maxCacheSize,
		);
	};

	const getInvalidationOps = (
		ctx: GenericEndpointContext,
		storageMode: "secondary-storage" | "database" | "none",
	): InvalidationOps => {
		if (storageMode === "none") {
			return createMemoryInvalidationOps(
				Math.max(
					(options.maxValiditySec ?? DEFAULT_MAX_VALIDITY_SEC) * 2,
					DEFAULT_INVALIDATION_TTL_SEC,
				),
			);
		}
		const dbOps = createDBInvalidationOps(ctx.context.adapter);
		if (ctx.context.secondaryStorage) {
			const maxTtl = options.maxValiditySec ?? DEFAULT_MAX_VALIDITY_SEC;
			const invalidationTtl = Math.max(
				maxTtl * 2,
				DEFAULT_INVALIDATION_TTL_SEC,
			);
			const ssOps = createSecondaryStorageInvalidationOps(
				ctx.context.secondaryStorage,
				invalidationTtl,
			);
			return options.storeInDatabase ? createDualInvalidationOps(dbOps, ssOps) : ssOps;
		}
		return dbOps;
	};

	const getNonceStore = (
		ctx: GenericEndpointContext,
		storageMode: "secondary-storage" | "database" | "none",
	) => {
		if (storageMode === "none") {
			return createMemoryNonceStore();
		}
		if (ctx.context.secondaryStorage) {
			const ssStore = createSecondaryStorageNonceStore(
				ctx.context.secondaryStorage,
				ctx.context.logger,
			);
			return options.storeInDatabase
				? createDualNonceStore(
						createAdapterNonceStore(ctx.context.adapter, ctx.context.logger),
						ssStore,
					)
				: ssStore;
		}
		return createAdapterNonceStore(ctx.context.adapter, ctx.context.logger);
	};

	const scheduleCleanup = async (ctx: GenericEndpointContext) => {
		if (
			(options.cleanupStrategy ?? "auto") !== "auto" ||
			!options.storeInDatabase ||
			!ctx.context.secondaryStorage
		) {
			return;
		}
		await createErc8128CleanupScheduler({
			adapter: ctx.context.adapter,
			secondaryStorage: ctx.context.secondaryStorage,
			strategy: "auto",
			throttleSec: cleanupThrottleSec,
		}).schedule();
	};

	const createEphemeralSignatureSession = (
		user: User,
		result: Extract<VerifyResult, { ok: true }>,
		request?: Request,
	): {
		session: Session;
		user: User;
	} => {
		const keyId = result.params.keyid.toLowerCase();
		const createdAt = new Date(result.params.created * 1000);
		const expiresAt = new Date(result.params.expires * 1000);
		const token = `erc8128:${keyId}:${result.params.created}:${result.params.expires}`;

		return {
			user,
			session: {
				id: token,
				userId: user.id,
				token,
				expiresAt,
				createdAt,
				updatedAt: createdAt,
				ipAddress: null,
				userAgent: request?.headers.get("user-agent") ?? null,
			},
		};
	};

	const createCachedVerifyMessage = (
		ctx: GenericEndpointContext,
		storageMode: "secondary-storage" | "database" | "none",
	): CachedVerifyMessageOps => {
		if (!replayableEnabled || storageMode === "none") {
			return {
				verifyMessage: options.verifyMessage,
				pending: null,
				async persist() {},
			};
		}

		const cache = getCache(ctx);
		let pending: CachedVerifyMessageOps["pending"] = null;

		return {
			pending,
			verifyMessage: async (args) => {
				cache.sweep();
				const cacheKey = getErc8128CacheKey({
					address: args.address,
					signature: args.signature,
					messageRaw: args.message.raw,
				});
				const cached = await cache.get(cacheKey);
				if (cached) {
					return true;
				}

				const verified = await options.verifyMessage(args);
				if (verified) {
					pending = {
						cacheKey,
						address: args.address.toLowerCase(),
						signatureHash: getErc8128SignatureHash(args.signature),
					};
				}
				return verified;
			},
			async persist(result) {
				if (!pending || !result.replayable) {
					return;
				}
				const nowSec = Math.floor(Date.now() / 1000);
				const ttlSec = Math.max(result.params.expires - nowSec, 1);
				await cache.set({
					key: pending.cacheKey,
					value: {
						verified: true,
						expires: result.params.expires,
					},
					ttlSec,
					address: pending.address,
					chainId: result.chainId,
					signatureHash: pending.signatureHash,
					expiresAt: new Date(result.params.expires * 1000),
				});
				pending = null;
			},
		};
	};

	const findOrCreateWalletUser = async (
		ctx: GenericEndpointContext,
		walletAddress: string,
		chainId: number,
		email?: string,
	): Promise<User | null> => {
		// 1. Exact match: address + chainId
		const existingWallet: WalletAddress | null =
			await ctx.context.adapter.findOne({
				model: "walletAddress",
				where: [
					{ field: "address", operator: "eq", value: walletAddress },
					{ field: "chainId", operator: "eq", value: chainId },
				],
			});

		if (existingWallet) {
			const user = await ctx.context.adapter.findOne<User>({
				model: "user",
				where: [{ field: "id", operator: "eq", value: existingWallet.userId }],
			});
			if (user) return user;
		}

		// 2. Same address on a different chain → reuse that user
		const anyWallet: WalletAddress | null = await ctx.context.adapter.findOne({
			model: "walletAddress",
			where: [{ field: "address", operator: "eq", value: walletAddress }],
		});

		let user: User | null = null;
		if (anyWallet) {
			user = await ctx.context.adapter.findOne({
				model: "user",
				where: [{ field: "id", operator: "eq", value: anyWallet.userId }],
			});
		}

		// 3. Create new user if none found
		if (!user) {
			const isAnon = options.anonymous ?? true;
			if (!isAnon && !email) {
				return null;
			}
			const domain = options.emailDomainName ?? getOrigin(ctx.context.baseURL);
			const userEmail = !isAnon && email ? email : `${walletAddress}@${domain}`;
			const { name, avatar } =
				(await options.ensLookup?.({ walletAddress })) ?? {};

			user = await ctx.context.internalAdapter.createUser({
				name: name ?? walletAddress,
				email: userEmail,
				image: avatar ?? "",
			});

			await ctx.context.adapter.create({
				model: "walletAddress",
				data: {
					userId: user.id,
					address: walletAddress,
					chainId,
					isPrimary: true,
					createdAt: new Date(),
				},
			});

			await ctx.context.internalAdapter.createAccount({
				userId: user.id,
				providerId: "erc8128",
				accountId: `${walletAddress}:${chainId}`,
				createdAt: new Date(),
				updatedAt: new Date(),
			});

			return user;
		}

		// 4. Existing user, new chain → add wallet + account
		if (!existingWallet) {
			await ctx.context.adapter.create({
				model: "walletAddress",
				data: {
					userId: user.id,
					address: walletAddress,
					chainId,
					isPrimary: false,
					createdAt: new Date(),
				},
			});

			await ctx.context.internalAdapter.createAccount({
				userId: user.id,
				providerId: "erc8128",
				accountId: `${walletAddress}:${chainId}`,
				createdAt: new Date(),
				updatedAt: new Date(),
			});
		}

		return user;
	};

	const verifyBodySchema = z
		.object({
			email: z.email().optional(),
		})
		.optional()
		.refine((data) => options.anonymous !== false || !!data?.email, {
			message:
				"Email is required when the anonymous plugin option is disabled.",
			path: ["email"],
		});

	const createRequestContext = (
		authContext: AuthContext<BetterAuthOptions>,
		request: Request,
	): GenericEndpointContext => {
		return {
			request,
			headers: request.headers,
			context: cloneAuthContextForRequest(authContext, request),
		} as GenericEndpointContext;
	};

	const getServerConfig = async (
		ctx: GenericEndpointContext,
	): Promise<Erc8128ServerConfig> => {
		const storageMode = await ensureStorageMode(ctx);
		const baseURL = ctx.context.baseURL;

		return {
			...formatDiscoveryDocument({
				verificationEndpoint:
					storageMode === "none" ? undefined : `${baseURL}/erc8128/verify`,
				invalidationEndpoint:
					replayableEnabled && storageMode !== "none"
						? `${baseURL}/erc8128/invalidate`
						: undefined,
				maxValiditySec: options.maxValiditySec,
				routePolicy: options.routePolicy
					? normalizeRoutePolicyConfig(options.routePolicy, baseURL)
					: undefined,
			}),
		};
	};

	const verifyRequestInternal = async (
		ctx: GenericEndpointContext,
		request: Request,
		policy?: RoutePolicy,
	): Promise<Erc8128VerifyRequestResult> => {
		const storageMode = await ensureStorageMode(ctx);
		await scheduleCleanup(ctx);
		if (storageMode === "none" && policy?.replayable) {
			warnReplayableNoStorage();
			return {
				ok: false,
				response: jsonErrorResponse(
					401,
					{
						error: "erc8128_verification_failed",
						reason: "replayable_requires_storage",
						detail:
							"Replayable route policy requires database or secondaryStorage",
					},
					{
						"WWW-Authenticate": WWW_AUTHENTICATE_HEADER,
					},
				),
				responseHeaders: new Headers({
					"WWW-Authenticate": WWW_AUTHENTICATE_HEADER,
				}),
			};
		}

		const signature = request.headers.get("signature");
		const signatureInput = request.headers.get("signature-input");
		if (!signature || !signatureInput) {
			const responseHeaders = new Headers({
				"WWW-Authenticate": WWW_AUTHENTICATE_HEADER,
			});
			return {
				ok: false,
				response: jsonErrorResponse(
					401,
					{
						error: "erc8128_verification_failed",
						reason: "missing_signature",
						detail: "Signature and Signature-Input headers are required",
					},
					Object.fromEntries(responseHeaders.entries()),
				),
				responseHeaders,
			};
		}

		const invalidationOps =
			replayableEnabled && storageMode !== "none"
				? getInvalidationOps(ctx, storageMode)
				: null;
		const hintedKeyId =
			extractKeyIdFromSignatureInput(signatureInput)?.toLowerCase() ?? null;
		const prefetchedKeyIdInvalidations =
			invalidationOps && hintedKeyId
				? invalidationOps.findByKeyId(hintedKeyId)
				: null;
		const prefetchedSignatureInvalidation =
			invalidationOps && hintedKeyId
				? invalidationOps.findBySignature(signature, hintedKeyId)
				: null;

		const getKeyIdInvalidations = (keyid: string) => {
			const normalizedKeyId = keyid.toLowerCase();
			if (prefetchedKeyIdInvalidations && hintedKeyId === normalizedKeyId) {
				return prefetchedKeyIdInvalidations;
			}
			return invalidationOps
				? invalidationOps.findByKeyId(normalizedKeyId)
				: Promise.resolve([]);
		};

		const getSignatureInvalidation = (value: string, keyId: string) => {
			const normalizedKeyId = keyId.toLowerCase();
			if (
				prefetchedSignatureInvalidation &&
				value === signature &&
				hintedKeyId === normalizedKeyId
			) {
				return prefetchedSignatureInvalidation;
			}
			return invalidationOps
				? invalidationOps.findBySignature(value, normalizedKeyId)
				: Promise.resolve(null);
		};

		const cachedVerifyMessage = createCachedVerifyMessage(ctx, storageMode);
		const verifier = createVerifierClient({
			verifyMessage: cachedVerifyMessage.verifyMessage,
			nonceStore: getNonceStore(ctx, storageMode),
			defaults: {
				maxValiditySec: options.maxValiditySec,
				clockSkewSec: options.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC,
				maxSignatureVerifications: MAX_SIGNATURE_VERIFICATIONS,
				...(replayableEnabled
					? {
							replayableNotBefore: async (keyid: string) => {
								const records = await getKeyIdInvalidations(keyid);
								const keyRecord = records.find(
									(record) => !record.signatureHash,
								);
								return keyRecord?.notBefore ?? null;
							},
							replayableInvalidated: async ({ keyid, signature }) => {
								const record = await getSignatureInvalidation(signature, keyid);
								return !!(
									record &&
									(!record.keyId || record.keyId === keyid.toLowerCase())
								);
							},
						}
					: {}),
			},
		});

			const responseHeaders: Record<string, string> = {};
		const result = await verifier.verifyRequest({
			request,
			policy,
			setHeaders: (name, value) => {
				responseHeaders[name] = value;
			},
		});
		const failure = getVerifyFailure(result);

		if (failure) {
			const reason =
				failure.reason === "replayable_invalidated"
					? "signature_invalidated"
					: failure.reason;
			const detail =
				failure.reason === "replayable_invalidated"
					? "Signature has been explicitly invalidated"
					: failure.detail;
			return {
				ok: false,
				response: jsonErrorResponse(
					401,
					{
						error: "erc8128_verification_failed",
						reason,
						detail,
					},
					responseHeaders,
				),
				responseHeaders: toHeaders(responseHeaders),
			};
		}

		if (!result.ok) {
			// Unreachable: getVerifyFailure returns non-null for !ok results.
			// This branch exists solely for TypeScript narrowing.
			throw new Error("[better-auth][erc8128] Unexpected verification state");
		}

		await cachedVerifyMessage.persist(result).catch(() => {});

		return {
			ok: true,
			responseHeaders: toHeaders(responseHeaders),
			verification: result,
		};
	};

	const protectRequestInternal = async (
		ctx: GenericEndpointContext,
		request: Request,
		protectOptions?: Erc8128ProtectOptions,
	): Promise<Erc8128ProtectResult> => {
		const resolvedRoutePolicy = resolveRoutePolicy(
			options.routePolicy,
			request,
			ctx.context.baseURL,
		);

		if (resolvedRoutePolicy.skipVerification) {
			return {
				ok: true,
				authenticated: false,
				principal: null,
				protected: false,
				responseHeaders: new Headers(),
				source: "none",
				verification: null,
			};
		}

		const precedence = options.authPrecedence ?? "session-first";
		const hasSessionCookie = request.headers
			.get("cookie")
			?.includes(ctx.context.authCookies.sessionToken.name);
		const currentSessionPromise =
			protectOptions?.resolveSession &&
			hasSessionCookie &&
			precedence === "reject-on-mismatch"
				? protectOptions.resolveSession()
				: null;
		const currentSession =
			protectOptions?.resolveSession && hasSessionCookie && !currentSessionPromise
				? await protectOptions.resolveSession()
				: null;

		if (currentSession && precedence === "session-first") {
			return {
				ok: true,
				authenticated: true,
				principal: currentSession,
				protected: resolvedRoutePolicy.requireAuth,
				responseHeaders: new Headers(),
				source: "session",
				verification: null,
			};
		}

		const hasSignatureHeaders =
			!!request.headers.get("signature") &&
			!!request.headers.get("signature-input");
		if (!hasSignatureHeaders) {
			if (!resolvedRoutePolicy.requireAuth) {
				return {
					ok: true,
					authenticated: false,
					principal: null,
					protected: false,
					responseHeaders: new Headers(),
					source: "none",
					verification: null,
				};
			}

			return {
				ok: false,
				protected: true,
				response: jsonErrorResponse(
					401,
					{
						error: "erc8128_verification_failed",
						reason: "missing_signature",
						detail: "Signature and Signature-Input headers are required",
					},
					{
						"WWW-Authenticate": WWW_AUTHENTICATE_HEADER,
					},
				),
				responseHeaders: new Headers({
					"WWW-Authenticate": WWW_AUTHENTICATE_HEADER,
				}),
			};
		}

		const verificationResult = await verifyRequestInternal(
			ctx,
			request,
			resolvedRoutePolicy.policy,
		);
		if (!verificationResult.ok) {
			if (!resolvedRoutePolicy.requireAuth) {
				return {
					ok: true,
					authenticated: false,
					principal: null,
					protected: false,
					responseHeaders: verificationResult.responseHeaders,
					source: "none",
					verification: null,
				};
			}
			return {
				ok: false,
				protected: true,
				response: verificationResult.response,
				responseHeaders: verificationResult.responseHeaders,
			};
		}

		const walletUser = await findOrCreateWalletUser(
			ctx,
			verificationResult.verification.address,
			verificationResult.verification.chainId,
		);
		const resolvedCurrentSession = currentSessionPromise
			? await currentSessionPromise
			: currentSession;

		if (!walletUser) {
			return {
				ok: false,
				protected: resolvedRoutePolicy.requireAuth,
				response: jsonErrorResponse(401, {
					error: "erc8128_verification_failed",
					reason: "wallet_not_linked",
					detail:
						"Wallet is not linked to a Better Auth user and anonymous onboarding is disabled",
				}),
				responseHeaders: new Headers(),
			};
		}

		if (
			resolvedCurrentSession &&
			precedence === "reject-on-mismatch" &&
			resolvedCurrentSession.user.id !== walletUser.id
		) {
			return {
				ok: false,
				protected: resolvedRoutePolicy.requireAuth,
				response: jsonErrorResponse(401, {
					error: "erc8128_verification_failed",
					reason: "identity_mismatch",
					detail: "Session user does not match signature identity",
				}),
				responseHeaders: new Headers(),
			};
		}

		const principal =
			resolvedCurrentSession && precedence === "reject-on-mismatch"
				? resolvedCurrentSession
				: createEphemeralSignatureSession(
						walletUser,
						verificationResult.verification,
						request,
					);

		return {
			ok: true,
			authenticated: true,
			principal,
			protected: resolvedRoutePolicy.requireAuth,
			responseHeaders: verificationResult.responseHeaders,
			source: "signature",
			verification: verificationResult.verification,
		};
	};

	return {
		id: "erc8128",
		getServerApi(ctx: Promise<AuthContext> | AuthContext) {
			return {
				erc8128: {
					getConfig: async (request?: Request) => {
						const authContext = await ctx;
						if (!("erc8128" in authContext) || !authContext.erc8128) {
							throw new Error(
								"[better-auth][erc8128] ERC-8128 server API unavailable.",
							);
						}
						return (authContext.erc8128 as Erc8128ServerApi).getConfig(request);
					},
					protect: async (
						request: Request,
						protectOptions?: Erc8128ProtectOptions,
					) => {
						const authContext = await ctx;
						if (!("erc8128" in authContext) || !authContext.erc8128) {
							throw new Error(
								"[better-auth][erc8128] ERC-8128 server API unavailable.",
							);
						}
						return (authContext.erc8128 as Erc8128ServerApi).protect(
							request,
							protectOptions,
						);
					},
					verifyRequest: async (
						request: Request,
						verifyOptions?: Erc8128VerifyRequestOptions,
					) => {
						const authContext = await ctx;
						if (!("erc8128" in authContext) || !authContext.erc8128) {
							throw new Error(
								"[better-auth][erc8128] ERC-8128 server API unavailable.",
							);
						}
						return (authContext.erc8128 as Erc8128ServerApi).verifyRequest(
							request,
							verifyOptions,
						);
					},
				} satisfies Erc8128ServerApi,
			};
		},
		schema: mergeSchema(schema, options?.schema) as ERC8128Schema,
		init(ctx) {
			return {
				context: {
					erc8128: {
						getConfig: async (request?: Request) =>
							getServerConfig(
								createRequestContext(
									ctx as AuthContext<BetterAuthOptions>,
									request ??
										new Request(
											ctx.baseURL ||
												"http://localhost" +
													(ctx.options.basePath || "/api/auth"),
										),
								),
							),
						protect: async (
							request: Request,
							protectOptions?: Erc8128ProtectOptions,
						) =>
							protectRequestInternal(
								createRequestContext(
									ctx as AuthContext<BetterAuthOptions>,
									request,
								),
								request,
								protectOptions,
							),
						verifyRequest: async (
							request: Request,
							verifyOptions?: Erc8128VerifyRequestOptions,
						) =>
							verifyRequestInternal(
								createRequestContext(
									ctx as AuthContext<BetterAuthOptions>,
									request,
								),
								request,
								verifyOptions?.policy,
							),
					} satisfies Erc8128ServerApi,
				},
			};
		},
		hooks: {
			before: [
				{
					matcher(context: { request?: Request; headers?: Headers }) {
						if (context.request) {
							// Skip the plugin's own endpoints — they handle their own verification
							if (isPluginEndpoint(context.request)) {
								return false;
							}

							if (options.routePolicy) {
								return true;
							}
						}

						const headers = context.request?.headers || context.headers;
						if (!headers) {
							return false;
						}

						return !!(
							headers.get("signature") && headers.get("signature-input")
						);
					},
					handler: createAuthMiddleware(async (ctx: GenericEndpointContext) => {
						if (!ctx.request) {
							return;
						}

						if (isPluginEndpoint(ctx.request, ctx.context.baseURL)) {
							return;
						}

						const cookieHeader = ctx.request.headers.get("cookie") || "";
						const hasSessionCookie = cookieHeader.includes(
							ctx.context.authCookies.sessionToken.name,
						);
						const precedence = options.authPrecedence ?? "session-first";

						// session-first: skip signature verification when a session cookie exists
						if (hasSessionCookie && precedence === "session-first") {
							return;
						}

						const result = await protectRequestInternal(ctx, ctx.request, {
							resolveSession:
								hasSessionCookie && precedence === "reject-on-mismatch"
									? async () => {
											const session = await getSessionFromCtx(ctx);
											return session
												? {
														session: session.session,
														user: session.user,
													}
												: null;
										}
									: undefined,
						});

						if (!result.ok) {
							return result.response;
						}

						if (result.verification) {
							(ctx.context as typeof ctx.context & Record<string, unknown>)[
								ERC8128_VERIFICATION_CONTEXT_KEY
							] = result.verification;
						}

						if (result.principal && result.source === "signature") {
							ctx.context.session = result.principal;
						}
					}),
				},
			],
		},
		endpoints: {
			getErc8128Config: createAuthEndpoint(
				"/.well-known/erc8128",
				{
					method: "GET",
					metadata: HIDE_METADATA,
				},
				async (ctx) => ctx.json(await getServerConfig(ctx)),
			),
			verifyErc8128: createAuthEndpoint(
				"/erc8128/verify",
				{
					method: "POST",
					body: verifyBodySchema,
					requireRequest: true,
					cloneRequest: true,
				},
				async (ctx) => {
					const storageMode = await ensureStorageMode(ctx);
					await scheduleCleanup(ctx);
					if (storageMode === "none") {
						return new Response(null, { status: 404 });
					}
					// Verify endpoint requires request-bound, non-replayable signatures
					// (replayable/class-bound flexibility is for the middleware only)
					const verifier = createVerifierClient({
						verifyMessage: options.verifyMessage,
						nonceStore: getNonceStore(ctx, storageMode),
						defaults: {
							maxValiditySec: options.maxValiditySec,
							clockSkewSec: options.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC,
							maxSignatureVerifications: MAX_SIGNATURE_VERIFICATIONS,
							replayable: false,
						},
					});

					const responseHeaders: Record<string, string> = {};

					const sourceRequest = ctx.request!;
					const result = await verifier.verifyRequest({
						request: sourceRequest,
						setHeaders: (name, value) => {
							responseHeaders[name] = value;
						},
					});
					const verifyFailure = getVerifyFailure(result);
					if (verifyFailure) {
						return new Response(
							JSON.stringify({
								error: "erc8128_verification_failed",
								reason: verifyFailure.reason,
								detail: verifyFailure.detail,
							}),
							{
								status: 401,
								headers: {
									"Content-Type": "application/json",
									...responseHeaders,
								},
							},
						);
					}
					if (!result.ok) {
						throw new Error("[better-auth][erc8128] Unexpected verification state");
					}

					const key = parseErc8128KeyId(result.params.keyid);
					if (!key) {
						throw APIError.fromStatus("UNAUTHORIZED", {
							message: "Unauthorized: bad_keyid",
							status: 401,
						});
					}

					const { address: walletAddress, chainId } = key;
					const isAnon = options.anonymous ?? true;

					if (!isAnon && !ctx.body?.email) {
						throw APIError.fromStatus("BAD_REQUEST", {
							message: "Email is required when anonymous is disabled.",
							status: 400,
						});
					}

					const user = await findOrCreateWalletUser(
						ctx,
						walletAddress,
						chainId,
						ctx.body?.email,
					);
					if (!user) {
						throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
							message: "Failed to create or find user",
							status: 500,
						});
					}

					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						undefined,
						options.sessionExpiresIn
							? {
									expiresAt: new Date(
										Date.now() + options.sessionExpiresIn * 1000,
									),
								}
							: undefined,
					);

					await setSessionCookie(ctx, { session, user });

					return ctx.json({
						token: session.token,
						success: true,
						user: {
							id: user.id,
							walletAddress,
							chainId,
						},
					});
				},
			),
			...(replayableEnabled
				? {
						invalidateErc8128: createAuthEndpoint(
							"/erc8128/invalidate",
							{
								method: "POST",
								body: invalidateBodySchema,
								requireRequest: true,
								cloneRequest: true,
							},
							async (ctx) => {
								const storageMode = await ensureStorageMode(ctx);
								await scheduleCleanup(ctx);
								if (storageMode === "none") {
									return new Response(null, { status: 404 });
								}
								const verifier = createVerifierClient({
									verifyMessage: options.verifyMessage,
									nonceStore: getNonceStore(ctx, storageMode),
									defaults: {
										maxValiditySec: options.maxValiditySec,
										clockSkewSec:
											options.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC,
										maxSignatureVerifications: MAX_SIGNATURE_VERIFICATIONS,
										replayable: false,
									},
								});

								const responseHeaders: Record<string, string> = {};

								const sourceRequest = ctx.request!;
								const result = await verifier.verifyRequest({
									request: sourceRequest,
									setHeaders: (name, value) => {
										responseHeaders[name] = value;
									},
								});
								const verifyFailure = getVerifyFailure(result);
								if (verifyFailure) {
									return new Response(
										JSON.stringify({
											error: "erc8128_verification_failed",
											reason: verifyFailure.reason,
											detail: verifyFailure.detail,
										}),
										{
											status: 401,
											headers: {
												"Content-Type": "application/json",
												...responseHeaders,
											},
										},
									);
								}
								if (!result.ok) {
									throw new Error("[better-auth][erc8128] Unexpected verification state");
								}

								const invOps = getInvalidationOps(ctx, storageMode);
								const maxValidity = options.maxValiditySec;

								// Per-signature invalidation
								if (ctx.body?.signature) {
									const sigToInvalidate = ctx.body.signature;
									await invOps.upsertSignatureInvalidation(
										result.params.keyid,
										sigToInvalidate,
										maxValidity ?? DEFAULT_MAX_VALIDITY_SEC,
									);

									return ctx.json({
										success: true,
										invalidatedSignature: sigToInvalidate,
									});
								}

								// Per-keyId invalidation (default to now+1 so signatures created this second are invalidated)
								const notBefore =
									ctx.body?.notBefore ?? Math.floor(Date.now() / 1000) + 1;

									await invOps.upsertKeyIdNotBefore(
										result.params.keyid,
										notBefore,
										keyInvalidationWindowSec,
									);

								return ctx.json({
									success: true,
									invalidatedBefore: notBefore,
								});
							},
						),
					}
				: {}),
		},
		options,
		$ServerAPI: {
			erc8128: {} as Erc8128ServerApi,
		},
	} satisfies BetterAuthPluginWithServerApi<{ erc8128: Erc8128ServerApi }>;
};
