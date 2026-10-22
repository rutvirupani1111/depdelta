export type Files = Record<string, string>;

export declare function benignV1(): Files;
export declare function benignV2(): Files;
export declare function maliciousV2(): Files;
export declare function walletHookV2(): Files;
export declare function nativeAddon(version?: string): Files;
export declare function leftPad(version?: string): Files;
export declare function toBuffers(files: Files): Map<string, Buffer>;
