/**
 * Configuration for a single transcryptor
 */
export class TranscryptorConfig {
    // eslint-disable-next-line camelcase
    system_id: string;
    url: string;

    // eslint-disable-next-line camelcase
    constructor(system_id: string, url: string) {
        // eslint-disable-next-line camelcase
        this.system_id = system_id;
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