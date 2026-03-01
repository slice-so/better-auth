import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

export const walletAddressSchema = {
	walletAddress: {
		fields: {
			userId: {
				type: "string",
				references: {
					model: "user",
					field: "id",
				},
				required: true,
				index: true,
			},
			address: {
				type: "string",
				required: true,
			},
			chainId: {
				type: "number",
				required: true,
			},
			isPrimary: {
				type: "boolean",
				defaultValue: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;

export const invalidationSchema = {
	erc8128Invalidation: {
		fields: {
			keyId: {
				type: "string",
				required: true,
				unique: true,
			},
			notBefore: {
				type: "number",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;

export const schema = {
	...walletAddressSchema,
	...invalidationSchema,
} satisfies BetterAuthPluginDBSchema;

export type ERC8128Schema = typeof schema;
