import type {
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
import type { InferOptionSchema, User } from "../../types";
import { HIDE_METADATA } from "../../utils/hide-metadata";
import { getOrigin } from "../../utils/url";
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
import { parseErc8128KeyId } from "./utils";
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

export interface ERC8128PluginOptions {
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
	let cacheOps: VerificationCacheOps | null = null;
	let invalidationOpsInstance: InvalidationOps | null = null;
	let nonceStoreInstance: {
		consume: (key: string, ttlSeconds: number) => Promise<boolean>;
	} | null = null;
	let storageMode: "secondary-storage" | "database" | "none" | null = null;
	let warnedNoStorage = false;
	let warnedReplayableNoStorage = false;

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
		if (storageMode) return storageMode;
		if (ctx.context.secondaryStorage) {
			storageMode = "secondary-storage";
			return storageMode;
		}
		try {
			await ctx.context.internalAdapter.findVerificationValue(
				"__erc8128_probe__",
			);
			storageMode = "database";
			return storageMode;
		} catch {
			storageMode = "none";
			warnNoStorage();
			return storageMode;
		}
	};

	const getCache = (ctx: GenericEndpointContext): VerificationCacheOps => {
		if (!cacheOps) {
			const resolved: "secondary-storage" | "database" = ctx.context
				.secondaryStorage
				? "secondary-storage"
				: "database";
			cacheOps = createVerificationCacheOps(
				resolved,
				ctx.context.secondaryStorage,
				ctx.context.internalAdapter,
				fallbackCacheMap,
				maxCacheSize,
			);
		}
		return cacheOps;
	};

	const getInvalidationOps = (ctx: GenericEndpointContext): InvalidationOps => {
		if (!invalidationOpsInstance) {
			if (storageMode === "none") {
				invalidationOpsInstance = createMemoryInvalidationOps(
					Math.max(
						(options.maxValiditySec ?? DEFAULT_MAX_VALIDITY_SEC) * 2,
						DEFAULT_INVALIDATION_TTL_SEC,
					),
				);
				return invalidationOpsInstance;
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
				invalidationOpsInstance = options.storeInDatabase
					? createDualInvalidationOps(dbOps, ssOps)
					: ssOps;
			} else {
				invalidationOpsInstance = dbOps;
			}
		}
		return invalidationOpsInstance;
	};

	const getNonceStore = (ctx: GenericEndpointContext) => {
		if (!nonceStoreInstance) {
			if (storageMode === "none") {
				nonceStoreInstance = createMemoryNonceStore();
			} else if (ctx.context.secondaryStorage) {
				const ssStore = createSecondaryStorageNonceStore(
					ctx.context.secondaryStorage,
				);
				nonceStoreInstance = options.storeInDatabase
					? createDualNonceStore(
							createAdapterNonceStore(ctx.context.internalAdapter),
							ssStore,
						)
					: ssStore;
			} else {
				nonceStoreInstance = createAdapterNonceStore(
					ctx.context.internalAdapter,
				);
			}
		}
		return nonceStoreInstance;
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
	): VerifyMessageFn => {
		if (!replayableEnabled || storageMode === "none") {
			return options.verifyMessage;
		}

		const cache = getCache(ctx);
		const ttlSec = Math.max(
			options.maxValiditySec ?? DEFAULT_MAX_VALIDITY_SEC,
			1,
		);

		return async (args) => {
			cache.sweep();
			const cacheKey = `${args.address.toLowerCase()}:${args.signature}:${args.message.raw}`;
			const cached = await cache.get(cacheKey);
			if (cached) {
				return true;
			}

			const verified = await options.verifyMessage(args);
			if (verified) {
				await cache.set(
					cacheKey,
					{
						verified: true,
						expires: Math.floor(Date.now() / 1000) + ttlSec,
					},
					ttlSec,
				);
			}
			return verified;
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

	return {
		id: "erc8128",
		schema: mergeSchema(schema, options?.schema) as ERC8128Schema,
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
						const incomingHeaders = (ctx.request?.headers || ctx.headers) as
							| Headers
							| undefined;
						if (!incomingHeaders) {
							return;
						}

						if (
							ctx.request &&
							isPluginEndpoint(ctx.request, ctx.context.baseURL)
						) {
							return;
						}

						const cookieHeader = incomingHeaders.get("cookie") || "";
						const hasSessionCookie = cookieHeader.includes(
							ctx.context.authCookies.sessionToken.name,
						);
						const precedence = options.authPrecedence ?? "session-first";

						// session-first: skip signature verification when a session cookie exists
						if (hasSessionCookie && precedence === "session-first") {
							return;
						}

						const resolvedRoutePolicy = ctx.request
							? resolveRoutePolicy(
									options.routePolicy,
									ctx.request,
									ctx.context.baseURL,
								)
							: ({
									policy: undefined,
									requireAuth: false,
									skipVerification: false,
								} as const);
						if (resolvedRoutePolicy.skipVerification) {
							return;
						}

						await ensureStorageMode(ctx);
						if (storageMode === "none") {
							if (!resolvedRoutePolicy.requireAuth) {
								// In stateless mode, only explicitly protected routes run middleware.
								return;
							}
							if (resolvedRoutePolicy.policy?.replayable) {
								warnReplayableNoStorage();
								return new Response(
									JSON.stringify({
										error: "erc8128_verification_failed",
										reason: "replayable_requires_storage",
										detail:
											"Replayable route policy requires database or secondaryStorage",
									}),
									{
										status: 401,
										headers: { "Content-Type": "application/json" },
									},
								);
							}
						}

						const signature = incomingHeaders.get("signature");
						const signatureInput = incomingHeaders.get("signature-input");
						const hasSignatureHeaders = !!signature && !!signatureInput;

						if (!hasSignatureHeaders) {
							if (!resolvedRoutePolicy.requireAuth) {
								return;
							}
							return new Response(
								JSON.stringify({
									error: "erc8128_verification_failed",
									reason: "missing_signature",
									detail: "Signature and Signature-Input headers are required",
								}),
								{
									status: 401,
									headers: {
										"Content-Type": "application/json",
										"WWW-Authenticate":
											'Signature realm="erc8128", headers="@method @target-uri @authority"',
									},
								},
							);
						}

						const invalidationOps =
							replayableEnabled && storageMode !== "none"
								? getInvalidationOps(ctx)
								: null;
						const hintedKeyId = signatureInput
							? (extractKeyIdFromSignatureInput(
									signatureInput,
								)?.toLowerCase() ?? null)
							: null;
						const prefetchedKeyIdInvalidations =
							invalidationOps && hintedKeyId
								? invalidationOps.findByKeyId(hintedKeyId)
								: null;
						const prefetchedSignatureInvalidation =
							invalidationOps && signature
								? invalidationOps.findBySignature(signature)
								: null;

						const getKeyIdInvalidations = (keyid: string) => {
							const normalizedKeyId = keyid.toLowerCase();
							if (
								prefetchedKeyIdInvalidations &&
								hintedKeyId === normalizedKeyId
							) {
								return prefetchedKeyIdInvalidations;
							}
							return invalidationOps
								? invalidationOps.findByKeyId(normalizedKeyId)
								: Promise.resolve([]);
						};

						const getSignatureInvalidation = (value: string) => {
							if (prefetchedSignatureInvalidation && value === signature) {
								return prefetchedSignatureInvalidation;
							}
							return invalidationOps
								? invalidationOps.findBySignature(value)
								: Promise.resolve(null);
						};

						const verifier = createVerifierClient({
							verifyMessage: createCachedVerifyMessage(ctx),
							nonceStore: getNonceStore(ctx),
							defaults: {
								maxValiditySec: options.maxValiditySec,
								clockSkewSec: options.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC,
								maxSignatureVerifications: MAX_SIGNATURE_VERIFICATIONS,
								...(replayableEnabled
									? {
											replayableNotBefore: async (keyid: string) => {
												const records = await getKeyIdInvalidations(keyid);
												const keyRecord = records.find((r) => !r.signature);
												return keyRecord?.notBefore ?? null;
											},
											replayableInvalidated: async ({ keyid, signature }) => {
												const record =
													await getSignatureInvalidation(signature);
												return !!(
													record &&
													(!record.keyId ||
														record.keyId === keyid.toLowerCase())
												);
											},
										}
									: {}),
							},
						});

						const responseHeaders: Record<string, string> = {};

						if (!ctx.request) {
							if (!resolvedRoutePolicy.requireAuth) {
								return;
							}
							return new Response(
								JSON.stringify({
									error: "erc8128_verification_failed",
									reason: "missing_request_context",
									detail: "Unable to verify signature without request context",
								}),
								{
									status: 401,
									headers: {
										"Content-Type": "application/json",
										"WWW-Authenticate":
											'Signature realm="erc8128", headers="@method @target-uri @authority"',
									},
								},
							);
						}

						const result = await verifier.verifyRequest({
							request: ctx.request,
							policy: resolvedRoutePolicy.policy,
							setHeaders: (name, value) => {
								responseHeaders[name] = value;
							},
						});
						if (!result.ok) {
							if (!resolvedRoutePolicy.requireAuth) {
								return;
							}
							const reason =
								result.reason === "replayable_invalidated"
									? "signature_invalidated"
									: result.reason;
							const detail =
								result.reason === "replayable_invalidated"
									? "Signature has been explicitly invalidated"
									: result.detail;
							return new Response(
								JSON.stringify({
									error: "erc8128_verification_failed",
									reason,
									detail,
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

						(ctx.context as typeof ctx.context & Record<string, unknown>)[
							ERC8128_VERIFICATION_CONTEXT_KEY
						] = result;

						const walletAddress = result.address;
						const chainId = result.chainId;
						const walletUser = await findOrCreateWalletUser(
							ctx,
							walletAddress,
							chainId,
						);

						// reject-on-mismatch: if both session and signature are present
						// and resolve to different users, reject the request
						if (hasSessionCookie && precedence === "reject-on-mismatch") {
							const currentSession = await getSessionFromCtx(ctx);
							if (
								currentSession &&
								walletUser &&
								currentSession.user.id !== walletUser.id
							) {
								return new Response(
									JSON.stringify({
										error: "erc8128_verification_failed",
										reason: "identity_mismatch",
										detail: "Session user does not match signature identity",
									}),
									{
										status: 401,
										headers: {
											"Content-Type": "application/json",
										},
									},
								);
							}
							if (!currentSession && walletUser) {
								ctx.context.session = createEphemeralSignatureSession(
									walletUser,
									result,
									ctx.request,
								);
							}
							return;
						}

						if (
							walletUser &&
							(precedence === "signature-first" || !hasSessionCookie)
						) {
							ctx.context.session = createEphemeralSignatureSession(
								walletUser,
								result,
								ctx.request,
							);
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
				async (ctx) => {
					await ensureStorageMode(ctx);
					const baseURL = ctx.context.baseURL;

					return ctx.json({
						...formatDiscoveryDocument({
							verificationEndpoint:
								storageMode === "none"
									? undefined
									: `${baseURL}/erc8128/verify`,
							invalidationEndpoint:
								replayableEnabled && storageMode !== "none"
									? `${baseURL}/erc8128/invalidate`
									: undefined,
							maxValiditySec: options.maxValiditySec,
							routePolicy: options.routePolicy
								? normalizeRoutePolicyConfig(options.routePolicy, baseURL)
								: undefined,
						}),
						capabilities: {
							persistent_storage: storageMode !== "none",
							request_bound_middleware_only: storageMode === "none",
						},
					});
				},
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
					await ensureStorageMode(ctx);
					if (storageMode === "none") {
						return new Response(null, { status: 404 });
					}
					// Verify endpoint requires request-bound, non-replayable signatures
					// (replayable/class-bound flexibility is for the middleware only)
					const verifier = createVerifierClient({
						verifyMessage: options.verifyMessage,
						nonceStore: getNonceStore(ctx),
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
					if (!result.ok) {
						return new Response(
							JSON.stringify({
								error: "erc8128_verification_failed",
								reason: result.reason,
								detail: result.detail,
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
								await ensureStorageMode(ctx);
								if (storageMode === "none") {
									return new Response(null, { status: 404 });
								}
								const verifier = createVerifierClient({
									verifyMessage: options.verifyMessage,
									nonceStore: getNonceStore(ctx),
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
								if (!result.ok) {
									return new Response(
										JSON.stringify({
											error: "erc8128_verification_failed",
											reason: result.reason,
											detail: result.detail,
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

								const invOps = getInvalidationOps(ctx);
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
	} satisfies BetterAuthPlugin;
};
