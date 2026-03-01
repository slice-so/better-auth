import { parseKeyId } from "@slicekit/erc8128";
import { toChecksumAddress } from "../../utils/hashing";

export function parseErc8128KeyId(keyId: string): {
	address: string;
	chainId: number;
} | null {
	const parsed = parseKeyId(keyId);
	if (!parsed) {
		return null;
	}
	return {
		address: toChecksumAddress(parsed.address),
		chainId: parsed.chainId,
	};
}
