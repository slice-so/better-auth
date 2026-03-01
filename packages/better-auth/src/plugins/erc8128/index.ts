import type { BetterAuthPlugin } from "@better-auth/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@better-auth/core/api";
import { createVerifierClient, type VerifyResult } from "@slicekit/erc8128";
import { serializeSignedCookie } from "better-call";
import * as z from "zod";
import { APIError } from "../../api";
import { setSessionCookie } from "../../cookies";
import { mergeSchema } from "../../db/schema";
import type { User } from "../../types";
import { getOrigin } from "../../utils/url";
import { createAdapterNonceStore } from "./nonce-store";
import type { ERC8128Schema } from "./schema";
import { schema, walletAddressSchema } from "./schema";
import type { ERC8128PluginOptions, WalletAddress } from "./types";
import { parseErc8128KeyId } from "./utils";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		erc8128: {
			creator: typeof erc8128;
		};
	}
}

const verifyBodySchema = z
	.object({
		email: z.email().optional(),
	})
	.optional();

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

const MAX_CACHE_SIZE = 10_000;

function addToCache(cache: Map<string, CacheValue>, key: string, value: CacheValue) {
	if (cache.has(key)) {
		cache.delete(key);
	}
	cache.set(key, value);
	if (cache.size > MAX_CACHE_SIZE) {
		const oldest = cache.keys().next().value;
		if (oldest) cache.delete(oldest);
	}
}

function upsertInvalidation(
	adapter: { findOne: Function; create: Function; update: Function },
	keyId: string,
	notBefore: number,
) {
	return adapter
		.findOne({
			model: "erc8128Invalidation",
			where: [{ field: "keyId", operator: "eq", value: keyId }],
		})
		.then(async (existing: any) => {
			if (!existing) {
				await adapter.create({
					model: "erc8128Invalidation",
					data: {
						keyId,
						notBefore,
						updatedAt: new Date(),
					},
				});
				return;
			}

			await adapter.update({
				model: "erc8128Invalidation",
				where: [{ field: "id", operator: "eq", value: existing.id }],
				update: {
					notBefore,
					updatedAt: new Date(),
				},
			});
		});
}

async function resolveUserByWallet(ctx: any, walletAddress: string, chainId: number) {
	let user: User | null = null;

	const existingWalletAddress: WalletAddress | null = await ctx.context.adapter.findOne({
		model: "walletAddress",
		where: [
			{ field: "address", operator: "eq", value: walletAddress },
			{ field: "chainId", operator: "eq", value: chainId },
		],
	});

	if (existingWalletAddress) {
		user = await ctx.context.adapter.findOne({
			model: "user",
			where: [{ field: "id", operator: "eq", value: existingWalletAddress.userId }],
		});
	} else {
		const anyWalletAddress: WalletAddress | null = await ctx.context.adapter.findOne({
			model: "walletAddress",
			where: [{ field: "address", operator: "eq", value: walletAddress }],
		});

		if (anyWalletAddress) {
			user = await ctx.context.adapter.findOne({
				model: "user",
				where: [{ field: "id", operator: "eq", value: anyWalletAddress.userId }],
			});
		}
	}

	return { user, existingWalletAddress };
}

async function ensureWalletUser(ctx: any, options: ERC8128PluginOptions, args: { walletAddress: string; chainId: number; email?: string | undefined }) {
	const { walletAddress, chainId, email } = args;
	const isAnon = options.anonymous ?? true;

	if (!isAnon && !email) {
		throw APIError.fromStatus("BAD_REQUEST", {
			message: "Email is required when anonymous is disabled.",
			status: 400,
		});
	}

	let { user, existingWalletAddress } = await resolveUserByWallet(
		ctx,
		walletAddress,
		chainId,
	);

	if (!user) {
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
	} else if (!existingWalletAddress) {
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
}

export const erc8128 = (options: ERC8128PluginOptions) => {
	const verificationCache = new Map<string, CacheValue>();

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
					handler: createAuthMiddleware(async (ctx: any) => {
						const authHeader =
							ctx.request?.headers.get("authorization") ||
							ctx.headers?.get("authorization") ||
							"";
						if (!authHeader.toLowerCase().startsWith("erc-8128 ")) {
							return;
						}

						const nonceStore =
							options.nonceStore ?? createAdapterNonceStore(ctx.context.internalAdapter);

						const verifier = createVerifierClient({
							verifyMessage: options.verifyMessage,
							nonceStore,
							defaults: {
								...options.defaultPolicy,
								maxValiditySec: options.maxValiditySec ?? 300,
								clockSkewSec: options.clockSkewSec ?? 30,
								replayable:
									options.defaultPolicy?.replayable ??
									(options.allowReplayable ?? false),
								...(options.allowReplayable
									? {
											replayableNotBefore: async (keyid: string) => {
												const record = await ctx.context.adapter.findOne({
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

						let result: VerifyResult | null = null;
						if (signature && options.allowReplayable) {
							const cached = verificationCache.get(signature);
							if (cached && cached.expires > Math.floor(Date.now() / 1000)) {
								const notBeforeRecord = await ctx.context.adapter.findOne({
									model: "erc8128Invalidation",
									where: [
										{ field: "keyId", operator: "eq", value: cached.keyId },
									],
								});

								if (!notBeforeRecord || cached.created >= notBeforeRecord.notBefore) {
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

						if (signature && result.replayable && options.allowReplayable) {
							addToCache(verificationCache, signature, {
								address: result.address,
								chainId: result.chainId,
								keyId: result.params.keyid,
								expires: result.params.expires,
								created: result.params.created,
							});
						}

						const walletAddress = result.address;
						const chainId = result.chainId;
						const found = await ctx.context.adapter.findOne({
							model: "walletAddress",
							where: [
								{ field: "address", operator: "eq", value: walletAddress },
								{ field: "chainId", operator: "eq", value: chainId },
							],
						});

						if (!found || options.createSession === false) {
							return;
						}

						const session = await ctx.context.internalAdapter.createSession(found.userId);
						const signedToken = await serializeSignedCookie(
							"",
							session.token,
							ctx.context.secret,
						);

						const existingHeaders = (ctx.request?.headers || ctx.headers) as Headers;
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
			verifyErc8128: createAuthEndpoint(
				"/erc8128/verify",
				{
					method: "POST",
					body: verifyBodySchema,
					requireRequest: true,
				},
				async (ctx: any) => {
					const nonceStore =
						options.nonceStore ?? createAdapterNonceStore(ctx.context.internalAdapter);
					const verifier = createVerifierClient({
						verifyMessage: options.verifyMessage,
						nonceStore,
						defaults: {
							...options.defaultPolicy,
							maxValiditySec: options.maxValiditySec ?? 300,
							clockSkewSec: options.clockSkewSec ?? 30,
							replayable:
								options.defaultPolicy?.replayable ??
								(options.allowReplayable ?? false),
							...(options.allowReplayable
								? {
										replayableNotBefore: async (keyid: string) => {
											const record = await ctx.context.adapter.findOne({
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

					const result = await verifier.verifyRequest({ request: ctx.request! });
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

					const user = await ensureWalletUser(ctx, options, {
						walletAddress: key.address,
						chainId: key.chainId,
						email: ctx.body?.email,
					});

					if (options.createSession === false) {
						return ctx.json({
							success: true,
							user: {
								id: user.id,
								walletAddress: key.address,
								chainId: key.chainId,
							},
						});
					}

					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						options.sessionExpiresIn
							? {
								expiresIn: options.sessionExpiresIn,
							  }
							: undefined,
					);

					await setSessionCookie(ctx, { session, user });

					return ctx.json({
						token: session.token,
						success: true,
						user: {
							id: user.id,
							walletAddress: key.address,
							chainId: key.chainId,
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
						async (ctx: any) => {
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

							const result = await verifier.verifyRequest({ request: ctx.request! });
							if (!result.ok) {
								throw APIError.fromStatus("UNAUTHORIZED", {
									message: `Unauthorized: ${result.reason}`,
									status: 401,
								});
							}

							const notBefore =
								ctx.body?.notBefore ?? Math.floor(Date.now() / 1000);

							await upsertInvalidation(
								ctx.context.adapter as any,
								result.params.keyid,
								notBefore,
							);

							for (const [sig, value] of verificationCache) {
								if (value.keyId === result.params.keyid && value.created < notBefore) {
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
