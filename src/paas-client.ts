import {
    BlindedGlobalSecretKey,
    DataPoint,
    EncryptedDataPoint,
    EncryptedPseudonym,
    GlobalPublicKey,
    PEPClient,
    Pseudonym,
} from "@nolai/libpep-wasm";
import {PseudonymizationDomain} from "./messages.js"; // TODO: This should be imported from libpep-wasm
import {Transcryptor, TranscryptorConfig} from "./transcryptor.js";
import {EncryptionContexts, SystemId} from "./sessions.js";

export interface PseudonymServiceConfig {
    blindedGlobalPrivateKey: BlindedGlobalSecretKey;
    globalPublicKey: GlobalPublicKey;
    transcryptors: TranscryptorConfig[];
}

export type AuthToken = string;

export class PseudonymService {
    private config: PseudonymServiceConfig;
    private transcryptors: Transcryptor[];
    private pepCryptoClient: PEPClient | null = null;

    public constructor(
        config: PseudonymServiceConfig,
        authTokens: Map<SystemId, AuthToken>,
    ) {
        this.config = config;
        this.transcryptors = config.transcryptors.map(
            (c) => new Transcryptor(c, authTokens.get(c.systemId)),
        );
    }

    public async init() {
        const sks = await Promise.all(
            this.transcryptors.map(async (t) => (await t.startSession()).keyShare),
        );
        this.pepCryptoClient = new PEPClient(
            this.config.blindedGlobalPrivateKey,
            sks,
        );
    }

    // private getTranscryptorOrder(order: "random" | "default" | number[]) {
    //   if (order === "default") {
    //     order = [...Array(this.config.transcryptors.length).keys()];
    //   } else if (order === "random" || !order) {
    //     order = [...Array(this.config.transcryptors.length).keys()].sort(
    //       () => Math.random() - 0.5,
    //     );
    //   }
    //   return order;
    // }

    public async pseudonymize(
        encryptedPseudonym: EncryptedPseudonym,
        sessionsFrom: EncryptionContexts,
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        // order?: "random" | number[], //TODO: I don't think default is the right word here
    ) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        // order = this.getTranscryptorOrder(order);

        for (const transcryptor of this.transcryptors) {
            let response = await transcryptor.pseudonymize(
                encryptedPseudonym,
                domainFrom,
                domainTo,
                sessionsFrom.get(transcryptor.getSystemId()),
                transcryptor.getSessionId(),
            );
            encryptedPseudonym = response;
            // TODO: Handle error if pseudonymization fails
        }

        return encryptedPseudonym;
    }

    public async pseudonymizeBatch(
        encryptedPseudonyms: EncryptedPseudonym[],
        sessionsFrom: EncryptionContexts,
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        // order?: "random" | number[], //TODO: I don't think default is the right word here
    ) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        // order = this.getTranscryptorOrder(order);

        for (const transcryptor of this.transcryptors) {
            encryptedPseudonyms = await transcryptor.pseudonymizeBatch(
                encryptedPseudonyms,
                domainFrom,
                domainTo,
                sessionsFrom.get(transcryptor.getSystemId()),
                transcryptor.getSessionId(),
            );
            // TODO: Handle error if pseudonymization fails
        }

        return encryptedPseudonyms;
    }

    public async encryptPseudonym(pseudonym: Pseudonym) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.encryptPseudonym(pseudonym);
    }

    public async encryptData(datapoint: DataPoint) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.encryptData(datapoint);
    }

    public async decryptPseudonym(encryptedPseudonym: EncryptedPseudonym) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.decryptPseudonym(encryptedPseudonym);
    }

    public async decryptData(encryptedData: EncryptedDataPoint) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.decryptData(encryptedData);
    }

    public getCurrentSessions(): EncryptionContexts {
        return new EncryptionContexts(new Map(
            this.transcryptors.map((t) => [t.getSystemId(), t.getSessionId()]),
        ));
    }

    public getTranscryptorStatus() {
        return this.transcryptors.map((t) => t.getStatus());
    }
}
