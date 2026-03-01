import type { BetterAuthPlugin } from "@better-auth/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@better-auth/core/api";
import type {
	NonceStore,
	VerifyMessageFn,
	VerifyPolicy,
	VerifyResult,
} from "@slicekit/erc8128";
import { createVerifierClient } from "@slicekit/erc8128";
import { serializeSignedCookie } from "better-call";
import * as z from "zod";
import { APIError } from "../../api";
import { setSessionCookie } from "../../cookies";
import { mergeSchema } from "../../db/schema";
import type { InferOptionSchema, User } from "../../types";
import { HIDE_METADATA } from "../../utils/hide-metadata";
import { getOrigin } from "../../utils/url";
import { createAdapterNonceStore } from "./nonce-store";
import type { ERC8128Schema } from "./schema";
import { schema, walletAddressSchema } from "./schema";
import type { ENSLookupArgs, ENSLookupResult, WalletAddress } from "./types";
import { parseErc8128KeyId } from "./utils";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		erc8128: {
			creator: typeof erc8128;
		};
	}
}

export interface ERC8128PluginOptions {
	verifyMessage: VerifyMessageFn;
	nonceStore?: NonceStore | undefined;
	defaultPolicy?: VerifyPolicy | undefined;
	createSession?: boolean | undefined;
	sessionExpiresIn?: number | undefined;
	allowReplayable?: boolean | undefined;
	maxValiditySec?: number | undefined;
	clockSkewSec?: number | undefined;
	emailDomainName?: string | undefined;
	anonymous?: boolean | undefined;
	ensLookup?: ((args: ENSLookupArgs) => Promise<ENSLookupResult>) | undefined;
	schema?: InferOptionSchema<typeof schema> | undefined;
	/**
	 * Max number of replayable signature entries to keep in memory.
	 *
	 * This cache is per-process only (not shared across instances), matching
	 * Better Auth's cookieCache model.
	 */
	cacheSize?: number | undefined;
}

const invalidateBodySchema = z
	.object({
		notBefore: z.number().int().positive().optional(),
	})
	.optional();

type CacheValue = {
	address: string;
	chainId: number;
	keyId: string;
	expires: number;
	created: number;
};

const DEFAULT_CACHE_SIZE = 10_000;
const CACHE_SWEEP_INTERVAL_MS = 60_000;

export const erc8128 = (options: ERC8128PluginOptions) => {
	/**
	 * Replayable signature verification cache (same operational model as cookieCache):
	 * - in-memory and per-process only (not shared across instances)
	 * - bounded by signature natural expiry (maxValiditySec)
	 * - intentionally simple (no external store/pluggable cache)
	 */
	const verificationCache = new Map<string, CacheValue>();
	const maxCacheSize = options.cacheSize ?? DEFAULT_CACHE_SIZE;
	let lastCacheSweepMs = 0;

	const sweepExpiredCacheEntries = () => {
		const nowMs = Date.now();
		if (nowMs - lastCacheSweepMs < CACHE_SWEEP_INTERVAL_MS) {
			return;
		}
		lastCacheSweepMs = nowMs;
		const nowSec = Math.floor(nowMs / 1000);
		for (const [sig, value] of verificationCache) {
			if (value.expires < nowSec) {
				verificationCache.delete(sig);
			}
		}
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
		schema: mergeSchema(
			options?.allowReplayable ? schema : walletAddressSchema,
			options?.schema,
		) as ERC8128Schema,
		hooks: {
			before: [
				{
					matcher(context: { request?: Request; headers?: Headers }) {
						const auth =
							context.request?.headers.get("authorization") ||
							context.headers?.get("authorization") ||
							"";
						return auth.toLowerCase().startsWith("erc-8128 ");
					},
					handler: createAuthMiddleware(async (ctx) => {
						const authHeader =
							ctx.request?.headers.get("authorization") ||
							ctx.headers?.get("authorization") ||
							"";
						if (!authHeader.toLowerCase().startsWith("erc-8128 ")) {
							return;
						}

						const nonceStore =
							options.nonceStore ??
							createAdapterNonceStore(ctx.context.internalAdapter);

						const verifier = createVerifierClient({
							verifyMessage: options.verifyMessage,
							nonceStore,
							defaults: {
								...options.defaultPolicy,
								maxValiditySec: options.maxValiditySec ?? 300,
								clockSkewSec: options.clockSkewSec ?? 30,
								replayable:
									options.defaultPolicy?.replayable ??
									options.allowReplayable ??
									false,
								...(options.allowReplayable
									? {
											replayableNotBefore: async (keyid: string) => {
												const record = await ctx.context.adapter.findOne<{
													notBefore: number;
												}>({
													model: "erc8128Invalidation",
													where: [
														{ field: "keyId", operator: "eq", value: keyid },
													],
												});
												return record?.notBefore ?? null;
											},
										}
									: {}),
							},
						});

						const signature =
							ctx.request?.headers.get("signature") ||
							ctx.headers?.get("signature") ||
							null;

						// Check replayable signature cache before full verification
						let result: VerifyResult | null = null;
						if (signature && options.allowReplayable) {
							const cached = verificationCache.get(signature);
							if (cached && cached.expires > Math.floor(Date.now() / 1000)) {
								const notBeforeRecord = await ctx.context.adapter.findOne<{
									notBefore: number;
								}>({
									model: "erc8128Invalidation",
									where: [
										{ field: "keyId", operator: "eq", value: cached.keyId },
									],
								});

								if (
									!notBeforeRecord ||
									cached.created >= notBeforeRecord.notBefore
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
											keyid: cached.keyId,
										},
										replayable: true,
										binding: "class-bound",
									};
								}
							}
						}

						result ??= await verifier.verifyRequest({ request: ctx.request! });
						if (!result.ok) {
							return;
						}

						// Cache replayable verification result (LRU eviction)
						if (signature && result.replayable && options.allowReplayable) {
							if (verificationCache.has(signature)) {
								verificationCache.delete(signature);
							}
							verificationCache.set(signature, {
								address: result.address,
								chainId: result.chainId,
								keyId: result.params.keyid,
								expires: result.params.expires,
								created: result.params.created,
							});
							if (verificationCache.size > maxCacheSize) {
								const oldest = verificationCache.keys().next().value;
								if (oldest) verificationCache.delete(oldest);
							}
						}

						const walletAddress = result.address;
						const chainId = result.chainId;
						const found = await ctx.context.adapter.findOne<WalletAddress>({
							model: "walletAddress",
							where: [
								{ field: "address", operator: "eq", value: walletAddress },
								{ field: "chainId", operator: "eq", value: chainId },
							],
						});

						if (!found || options.createSession === false) {
							return;
						}

						const session = await ctx.context.internalAdapter.createSession(
							found.userId,
						);
						const signedToken = await serializeSignedCookie(
							"",
							session.token,
							ctx.context.secret,
						);

						const existingHeaders = (ctx.request?.headers ||
							ctx.headers) as Headers;
						const headers = new Headers({
							...Object.fromEntries(existingHeaders.entries()),
						});
						const existingCookie = headers.get("cookie");
						const newCookie = `${ctx.context.authCookies.sessionToken.name}=${signedToken.replace("=", "")}`;
						headers.set(
							"cookie",
							existingCookie ? `${existingCookie}; ${newCookie}` : newCookie,
						);

						return {
							context: {
								headers,
							},
						};
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
					return ctx.json({
						verification_endpoint: `${baseURL}/erc8128/verify`,
						...(options.allowReplayable
							? { invalidation_endpoint: `${baseURL}/erc8128/invalidate` }
							: {}),
						signing_algorithms: ["eip191"],
						account_types: ["eoa", "erc1271"],
						replay_protection: {
							non_replayable: true,
							replayable: options.allowReplayable ?? false,
						},
						max_validity_sec: options.maxValiditySec ?? 300,
						clock_skew_sec: options.clockSkewSec ?? 30,
						keyid_format: "erc8128:<chainId>:<address>",
						signature_scheme: "rfc9421",
						default_binding: "request-bound",
						session_creation: options.createSession !== false,
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
					const nonceStore =
						options.nonceStore ??
						createAdapterNonceStore(ctx.context.internalAdapter);
					// Verify endpoint requires request-bound, non-replayable signatures
					// (replayable/class-bound flexibility is for the middleware only)
					const verifier = createVerifierClient({
						verifyMessage: options.verifyMessage,
						nonceStore,
						defaults: {
							maxValiditySec: options.maxValiditySec ?? 300,
							clockSkewSec: options.clockSkewSec ?? 30,
							replayable: false,
						},
					});

					const result = await verifier.verifyRequest({
						request: ctx.request!,
					});
					if (!result.ok) {
						throw APIError.fromStatus("UNAUTHORIZED", {
							message: `Unauthorized: ${result.reason}`,
							status: 401,
						});
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

					// Look for existing user by their wallet addresses
					let user: User | null = null;

					// Check if there's a wallet address record for this exact address+chainId combination
					const existingWalletAddress: WalletAddress | null =
						await ctx.context.adapter.findOne({
							model: "walletAddress",
							where: [
								{ field: "address", operator: "eq", value: walletAddress },
								{ field: "chainId", operator: "eq", value: chainId },
							],
						});

					if (existingWalletAddress) {
						// Get the user associated with this wallet address
						user = await ctx.context.adapter.findOne({
							model: "user",
							where: [
								{
									field: "id",
									operator: "eq",
									value: existingWalletAddress.userId,
								},
							],
						});
					} else {
						// No exact match found, check if this address exists on any other chain
						const anyWalletAddress: WalletAddress | null =
							await ctx.context.adapter.findOne({
								model: "walletAddress",
								where: [
									{ field: "address", operator: "eq", value: walletAddress },
								],
							});

						if (anyWalletAddress) {
							// Same address exists on different chain, get that user
							user = await ctx.context.adapter.findOne({
								model: "user",
								where: [
									{
										field: "id",
										operator: "eq",
										value: anyWalletAddress.userId,
									},
								],
							});
						}
					}

					// Create new user if none exists
					if (!user) {
						const domain =
							options.emailDomainName ?? getOrigin(ctx.context.baseURL);
						const userEmail =
							!isAnon && ctx.body?.email
								? ctx.body.email
								: `${walletAddress}@${domain}`;
						const { name, avatar } =
							(await options.ensLookup?.({ walletAddress })) ?? {};

						user = await ctx.context.internalAdapter.createUser({
							name: name ?? walletAddress,
							email: userEmail,
							image: avatar ?? "",
						});

						// Create wallet address record
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

						// Create account record for wallet authentication
						await ctx.context.internalAdapter.createAccount({
							userId: user.id,
							providerId: "erc8128",
							accountId: `${walletAddress}:${chainId}`,
							createdAt: new Date(),
							updatedAt: new Date(),
						});
					} else if (!existingWalletAddress) {
						// User exists, add this new chainId to existing user's addresses
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

						// Create account record for this new wallet+chain combination
						await ctx.context.internalAdapter.createAccount({
							userId: user.id,
							providerId: "erc8128",
							accountId: `${walletAddress}:${chainId}`,
							createdAt: new Date(),
							updatedAt: new Date(),
						});
					}

					if (options.createSession === false) {
						return ctx.json({
							success: true,
							user: {
								id: user.id,
								walletAddress,
								chainId,
							},
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
			...(options.allowReplayable
				? {
						invalidateErc8128: createAuthEndpoint(
							"/erc8128/invalidate",
							{
								method: "POST",
								body: invalidateBodySchema,
								requireRequest: true,
							},
							async (ctx) => {
								const nonceStore =
									options.nonceStore ??
									createAdapterNonceStore(ctx.context.internalAdapter);
								const verifier = createVerifierClient({
									verifyMessage: options.verifyMessage,
									nonceStore,
									defaults: {
										...options.defaultPolicy,
										replayable: false,
										maxValiditySec: options.maxValiditySec ?? 300,
										clockSkewSec: options.clockSkewSec ?? 30,
									},
								});

								const result = await verifier.verifyRequest({
									request: ctx.request!,
								});
								if (!result.ok) {
									throw APIError.fromStatus("UNAUTHORIZED", {
										message: `Unauthorized: ${result.reason}`,
										status: 401,
									});
								}

								const notBefore =
									ctx.body?.notBefore ?? Math.floor(Date.now() / 1000);

								// Upsert invalidation record
								const existing = await ctx.context.adapter.findOne<{
									id: string;
								}>({
									model: "erc8128Invalidation",
									where: [
										{
											field: "keyId",
											operator: "eq",
											value: result.params.keyid,
										},
									],
								});

								if (!existing) {
									await ctx.context.adapter.create({
										model: "erc8128Invalidation",
										data: {
											keyId: result.params.keyid,
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
								for (const [sig, value] of verificationCache) {
									if (
										value.keyId === result.params.keyid &&
										value.created < notBefore
									) {
										verificationCache.delete(sig);
									}
								}

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
