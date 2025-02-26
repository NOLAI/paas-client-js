/**
 * Configuration for a single transcryptor
 */
export class TranscryptorConfig {
    systemId: string;
    url: string;

    constructor(systemId: string, url: string) {
        this.systemId = systemId;
        this.url = url;
    }
}

/**
 * Configuration for the PAAS service
 */
export interface PAASConfig {
    blinded_global_secret_key: string;
    global_public_key: string;
    transcryptors: TranscryptorConfig[];
}