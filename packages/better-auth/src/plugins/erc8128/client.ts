import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { erc8128 } from ".";

export const erc8128Client = () => {
	return {
		id: "erc8128",
		$InferServerPlugin: {} as ReturnType<typeof erc8128>,
	} satisfies BetterAuthClientPlugin;
};
