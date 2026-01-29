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
  blinded_global_keys: {
    pseudonym: string;
    attribute: string;
  };
  global_public_keys: {
    pseudonym: string;
    attribute: string;
  };
  transcryptors: TranscryptorConfig[];
}
