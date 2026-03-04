import type {
	BetterAuthPlugin,
	GenericEndpointContext,
} from "@better-auth/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@better-auth/core/api";
import type {
	VerifyMessageFn,
	VerifyPolicy,
	VerifyResult,
} from "@slicekit/erc8128";
import { createVerifierClient } from "@slicekit/erc8128";
import * as z from "zod";
import { APIError } from "../../api";
import { setSessionCookie } from "../../cookies";
import { mergeSchema } from "../../db/schema";
import type { InferOptionSchema, User } from "../../types";
import { HIDE_METADATA } from "../../utils/hide-metadata";
import { getOrigin } from "../../utils/url";
import { createAdapterNonceStore } from "./nonce-store";
import { isPluginEndpoint, resolveRoutePolicy } from "./route-policy";
import type { ERC8128Schema } from "./schema";
import { schema } from "./schema";
import type { ENSLookupArgs, ENSLookupResult, WalletAddress } from "./types";
import { parseErc8128KeyId } from "./utils";
import type { CacheValue, VerificationCacheOps } from "./verification-cache";
import {
	createVerificationCacheOps,
	DEFAULT_CACHE_SIZE,
} from "./verification-cache";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		erc8128: {
			creator: typeof erc8128;
		};
	}
}

export interface ERC8128PluginOptions {
	verifyMessage: VerifyMessageFn;
	defaultPolicy?: VerifyPolicy | undefined;
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
	routePolicy?:
		| (Record<string, VerifyPolicy | false> & {
				default?: VerifyPolicy;
		  })
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

export const erc8128 = (options: ERC8128PluginOptions) => {
	const replayableEnabled =
		options.defaultPolicy?.replayable === true ||
		(options.routePolicy != null &&
			Object.values(options.routePolicy).some(
				(p) => typeof p === "object" && p !== null && p.replayable === true,
			));

	const fallbackCacheMap = new Map<string, CacheValue>();
	const maxCacheSize = options.cacheSize ?? DEFAULT_CACHE_SIZE;
	let cacheOps: VerificationCacheOps | null = null;

	const getCache = (ctx: GenericEndpointContext): VerificationCacheOps => {
		if (!cacheOps) {
			const resolved: "secondary-storage" | "database" | "memory" = ctx.context
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

							const resolvedRoutePolicy = resolveRoutePolicy(
								options.routePolicy,
								context.request,
							);
							if (
								resolvedRoutePolicy.requireAuth &&
								!resolvedRoutePolicy.skipVerification
							) {
								return true;
							}
						}

						const headers = context.request?.headers || context.headers;
						if (!headers) {
							return false;
						}

						const auth = headers.get("authorization") || "";
						if (auth.toLowerCase().startsWith("erc-8128 ")) {
							return true;
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

						// If a session cookie is present, skip ERC-8128 verification
						// and let normal session handling authenticate the request.
						const cookieHeader = incomingHeaders.get("cookie") || "";
						if (
							cookieHeader.includes(ctx.context.authCookies.sessionToken.name)
						) {
							return;
						}

						const resolvedRoutePolicy = ctx.request
							? resolveRoutePolicy(options.routePolicy, ctx.request)
							: ({
									policy: undefined,
									requireAuth: false,
									skipVerification: false,
								} as const);
						if (resolvedRoutePolicy.skipVerification) {
							return;
						}

						const authHeader = incomingHeaders.get("authorization") || "";
						const hasSignatureHeaders =
							!!incomingHeaders.get("signature") &&
							!!incomingHeaders.get("signature-input");

						if (
							!authHeader.toLowerCase().startsWith("erc-8128 ") &&
							!hasSignatureHeaders
						) {
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

						const verifier = createVerifierClient({
							verifyMessage: options.verifyMessage,
							nonceStore: createAdapterNonceStore(ctx.context.internalAdapter),
							defaults: {
								...options.defaultPolicy,
								maxValiditySec: options.maxValiditySec ?? 300,
								clockSkewSec: options.clockSkewSec ?? 30,
								maxSignatureVerifications: 1,
								replayable: options.defaultPolicy?.replayable ?? false,
								...(replayableEnabled
									? {
											replayableNotBefore: async (keyid: string) => {
												const records = await ctx.context.adapter.findMany<{
													signature?: string;
													notBefore: number;
												}>({
													model: "erc8128Invalidation",
													where: [
														{
															field: "keyId",
															operator: "eq",
															value: keyid.toLowerCase(),
														},
													],
												});
												const keyRecord = records.find(
													(r: { signature?: string }) => !r.signature,
												);
												return keyRecord?.notBefore ?? null;
											},
										}
									: {}),
							},
						});

						const signature =
							ctx.request?.headers.get("signature") ||
							ctx.headers?.get("signature") ||
							null;

						const responseHeaders: Record<string, string> = {};

						// Check replayable signature cache before full verification
						let result: VerifyResult | null = null;
						const cache = getCache(ctx);
						if (signature && replayableEnabled && !resolvedRoutePolicy.policy) {
							cache.sweep();

							const cached = await cache.get(signature);
							if (cached && cached.expires > Math.floor(Date.now() / 1000)) {
								// Single query returns both per-keyId notBefore and per-signature invalidation records
								type InvalidationRecord = {
									signature?: string;
									notBefore: number;
								};
								const invalidations =
									await ctx.context.adapter.findMany<InvalidationRecord>({
										model: "erc8128Invalidation",
										where: [
											{
												field: "keyId",
												operator: "eq",
												value: cached.keyId.toLowerCase(),
											},
										],
									});
								const notBeforeRecord = invalidations.find(
									(r: InvalidationRecord) => !r.signature,
								);
								const invalidatedRecord = invalidations.find(
									(r: InvalidationRecord) => r.signature === signature,
								);

								if (invalidatedRecord) {
									await cache.delete(signature);
								} else if (
									!notBeforeRecord ||
									cached.created > notBeforeRecord.notBefore
								) {
									result = {
										ok: true,
										address: cached.address as `0x${string}`,
										chainId: cached.chainId,
										label: "eth",
										components: ["@method", "@target-uri", "@authority"],
										params: {
											created: cached.created,
											expires: cached.expires,
											keyid: cached.keyId.toLowerCase(),
										},
										replayable: true,
										binding: "class-bound",
									};
								}
							}
						}

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

						if (!result) {
							// Start invalidation check in parallel with verification (fail early if invalidated)
							const invalidationPromise = signature
								? ctx.context.adapter.findOne({
										model: "erc8128Invalidation",
										where: [
											{
												field: "signature",
												operator: "eq",
												value: signature,
											},
										],
									})
								: Promise.resolve(null);

							const verificationPromise = verifier.verifyRequest({
								request: ctx.request,
								policy: resolvedRoutePolicy.policy,
								setHeaders: (name, value) => {
									responseHeaders[name] = value;
								},
							});

							const invalidatedRecord = await invalidationPromise;
							if (invalidatedRecord) {
								await cache.delete(signature!);
								if (!resolvedRoutePolicy.requireAuth) {
									return;
								}
								return new Response(
									JSON.stringify({
										error: "erc8128_verification_failed",
										reason: "signature_invalidated",
										detail: "Signature has been explicitly invalidated",
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

							result = await verificationPromise;
						}
						if (!result.ok) {
							if (!resolvedRoutePolicy.requireAuth) {
								return;
							}
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

						if (replayableEnabled) {
							const records = await ctx.context.adapter.findMany<{
								signature?: string;
								notBefore: number;
							}>({
								model: "erc8128Invalidation",
								where: [
									{
										field: "keyId",
										operator: "eq",
										value: result.params.keyid.toLowerCase(),
									},
								],
							});
							const notBeforeRecord = records.find(
								(r: { signature?: string }) => !r.signature,
							);
							if (
								notBeforeRecord &&
								result.params.created < notBeforeRecord.notBefore
							) {
								if (!resolvedRoutePolicy.requireAuth) {
									return;
								}
								return new Response(
									JSON.stringify({
										error: "erc8128_verification_failed",
										reason: "replayable_invalidated",
										detail: "Replayable signature was invalidated",
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
						}

						// Cache replayable verification result
						if (signature && result.replayable && replayableEnabled) {
							const ttlSec =
								result.params.expires - Math.floor(Date.now() / 1000);
							if (ttlSec > 0) {
								await cache.set(
									signature,
									{
										address: result.address,
										chainId: result.chainId,
										keyId: result.params.keyid.toLowerCase(),
										expires: result.params.expires,
										created: result.params.created,
									},
									ttlSec,
								);
							}
						}

						const walletAddress = result.address;
						const chainId = result.chainId;
						await findOrCreateWalletUser(ctx, walletAddress, chainId);
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
					const baseURL = ctx.context.baseURL;
					const routePolicies = options.routePolicy
						? Object.fromEntries(
								Object.entries(options.routePolicy).filter(
									([key, value]) => key !== "default" && value !== false,
								),
							)
						: undefined;
					return ctx.json({
						verification_endpoint: `${baseURL}/erc8128/verify`,
						...(replayableEnabled
							? { invalidation_endpoint: `${baseURL}/erc8128/invalidate` }
							: {}),
						signing_algorithms: ["eip191"],
						account_types: ["eoa", "erc1271"],
						replay_protection: {
							non_replayable: true,
							replayable: replayableEnabled,
						},
						max_validity_sec: options.maxValiditySec ?? 300,
						clock_skew_sec: options.clockSkewSec ?? 30,
						keyid_format: "erc8128:<chainId>:<address>",
						signature_scheme: "rfc9421",
						default_binding: "request-bound",
						...(routePolicies ? { route_policies: routePolicies } : {}),
					});
				},
			),
			verifyErc8128: createAuthEndpoint(
				"/erc8128/verify",
				{
					method: "POST",
					body: verifyBodySchema,
					requireRequest: true,
				},
				async (ctx) => {
					// Verify endpoint requires request-bound, non-replayable signatures
					// (replayable/class-bound flexibility is for the middleware only)
					const verifier = createVerifierClient({
						verifyMessage: options.verifyMessage,
						nonceStore: createAdapterNonceStore(ctx.context.internalAdapter),
						defaults: {
							maxValiditySec: options.maxValiditySec ?? 300,
							clockSkewSec: options.clockSkewSec ?? 30,
							maxSignatureVerifications: 1,
							replayable: false,
						},
					});

					const responseHeaders: Record<string, string> = {};

					const sourceRequest = ctx.request!;
					const hasBodyMethod =
						sourceRequest.method !== "GET" && sourceRequest.method !== "HEAD";
					const verificationRequest =
						hasBodyMethod && ctx.body !== undefined
							? new Request(sourceRequest.url, {
									method: sourceRequest.method,
									headers: sourceRequest.headers,
									body: JSON.stringify(ctx.body),
								})
							: sourceRequest;

					const result = await verifier.verifyRequest({
						request: verificationRequest,
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
							},
							async (ctx) => {
								const verifier = createVerifierClient({
									verifyMessage: options.verifyMessage,
									nonceStore: createAdapterNonceStore(
										ctx.context.internalAdapter,
									),
									defaults: {
										maxValiditySec: options.maxValiditySec ?? 300,
										clockSkewSec: options.clockSkewSec ?? 30,
										maxSignatureVerifications: 1,
										replayable: false,
									},
								});

								const responseHeaders: Record<string, string> = {};

								const sourceRequest = ctx.request!;
								const hasBodyMethod =
									sourceRequest.method !== "GET" &&
									sourceRequest.method !== "HEAD";
								const verificationRequest = hasBodyMethod
									? (() => {
											const headers = new Headers(sourceRequest.headers);
											headers.delete("content-length");
											const body =
												ctx.body === undefined
													? undefined
													: JSON.stringify(ctx.body);
											return new Request(sourceRequest.url, {
												method: sourceRequest.method,
												headers,
												body,
											});
										})()
									: sourceRequest;

								const result = await verifier.verifyRequest({
									request: verificationRequest,
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

								// Per-signature invalidation
								if (ctx.body?.signature) {
									const sigToInvalidate = ctx.body.signature;
									const maxValidity = options.maxValiditySec ?? 300;
									const expiresAt = Math.floor(Date.now() / 1000) + maxValidity;

									const existing = await ctx.context.adapter.findOne<{
										id: string;
									}>({
										model: "erc8128Invalidation",
										where: [
											{
												field: "signature",
												operator: "eq",
												value: sigToInvalidate,
											},
										],
									});
									if (!existing) {
										await ctx.context.adapter.create({
											model: "erc8128Invalidation",
											data: {
												signature: sigToInvalidate,
												keyId: result.params.keyid.toLowerCase(),
												notBefore: 0,
												expiresAt,
												updatedAt: new Date(),
											},
										});
									} else {
										await ctx.context.adapter.update({
											model: "erc8128Invalidation",
											where: [
												{
													field: "id",
													operator: "eq",
													value: existing.id,
												},
											],
											update: { expiresAt },
										});
									}

									const sigCache = getCache(ctx);
									await sigCache.delete(sigToInvalidate);

									return ctx.json({
										success: true,
										invalidatedSignature: sigToInvalidate,
									});
								}

								// Per-keyId invalidation (default to now+1 so signatures created this second are invalidated)
								const notBefore =
									ctx.body?.notBefore ?? Math.floor(Date.now() / 1000) + 1;

								// Upsert per-keyId invalidation record
								const keyRecords = await ctx.context.adapter.findMany<{
									id: string;
									signature?: string;
								}>({
									model: "erc8128Invalidation",
									where: [
										{
											field: "keyId",
											operator: "eq",
											value: result.params.keyid.toLowerCase(),
										},
									],
								});
								const existing = keyRecords.find(
									(r: { signature?: string }) => !r.signature,
								);

								if (!existing) {
									await ctx.context.adapter.create({
										model: "erc8128Invalidation",
										data: {
											keyId: result.params.keyid.toLowerCase(),
											notBefore,
											updatedAt: new Date(),
										},
									});
								} else {
									await ctx.context.adapter.update({
										model: "erc8128Invalidation",
										where: [
											{
												field: "id",
												operator: "eq",
												value: existing.id,
											},
										],
										update: {
											notBefore,
											updatedAt: new Date(),
										},
									});
								}

								// Evict cached entries that are now invalidated
								const keyIdCache = getCache(ctx);
								keyIdCache.evictByKeyId(
									result.params.keyid.toLowerCase(),
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
