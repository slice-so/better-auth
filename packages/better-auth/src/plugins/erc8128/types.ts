import type {
	NonceStore,
	VerifyMessageFn,
	VerifyPolicy,
} from "@slicekit/erc8128";
import type { InferOptionSchema } from "../../types";
import type { schema } from "./schema";

export interface WalletAddress {
	id: string;
	userId: string;
	address: string;
	chainId: number;
	isPrimary: boolean;
	createdAt: Date;
}

export interface ENSLookupArgs {
	walletAddress: string;
}

export interface ENSLookupResult {
	name?: string;
	avatar?: string;
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
}

export type { NonceStore, VerifyMessageFn, VerifyPolicy };
