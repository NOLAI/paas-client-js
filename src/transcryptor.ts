import {EncryptedPseudonym, SessionKeyShare} from "@nolai/libpep-wasm";
import {
    GetSessionResponse,
    PseudonymizationBatchRequest,
    PseudonymizationBatchResponse,
    PseudonymizationDomain,
    PseudonymizationRequest,
    PseudonymizationResponse,
    StartSessionResponse,
} from "./messages.js";
import {AuthToken} from "./paas-client.js";
import {EncryptionContext} from "./sessions.js";

export class TranscryptorConfig {
    public systemId: string;
    public url: string;

    public constructor(systemId: string, url: string) {
        this.systemId = systemId;
        this.url = url;
    }
}

export enum TranscryptorState {
    UNKNOWN = "unknown",
    ONLINE = "online",
    OFFLINE = "offline",
    ERROR = "error",
}

export class TranscryptorStatus {
    private state: string;
    private lastChecked: number;

    public constructor(state: TranscryptorState, lastChecked: number) {
        this.state = state;
        this.lastChecked = lastChecked;
    }
}

export class Transcryptor {
    private config: TranscryptorConfig;
    public authToken: AuthToken;
    private status: TranscryptorStatus;
    private sessionId: string | null;

    public constructor(config: TranscryptorConfig, authToken: AuthToken) {
        this.config = config;
        this.authToken = authToken;
        this.status = new TranscryptorStatus(TranscryptorState.UNKNOWN, Date.now());
        this.sessionId = null;
    }

    public async checkStatus() {
        const response = await fetch(this.config.url + "/status", {
            method: "GET",
            mode: "cors",
            headers: {
                Authorization: "Bearer " + this.authToken,
            },
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
            return err;
        }); // TODO check session id

        if (!response.ok) {
            this.status = new TranscryptorStatus(
                response.status === 404
                    ? TranscryptorState.OFFLINE
                    : TranscryptorState.ERROR,
                Date.now(),
            );
        } else {
            this.status = new TranscryptorStatus(
                TranscryptorState.ONLINE,
                Date.now(),
            );
        }
    }

    public async startSession() {
        const response = await fetch(this.config.url + "/sessions/start", {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + this.authToken,
            },
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
            return err;
        });

        if (response.ok) {
            const data: StartSessionResponse = await response.json();
            this.sessionId = data.session_id;

            return {
                sessionId: data.session_id,
                keyShare: SessionKeyShare.fromHex(data.key_share),
            };
        } else {
            throw new Error(
                `Failed to start session with ${this.config.systemId} at ${this.config.url}`,
            );
        }
    }

    public async pseudonymize(
        encryptedPseudonym: EncryptedPseudonym,
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        sessionFrom: EncryptionContext,
        sessionTo: EncryptionContext,
    ): Promise<EncryptedPseudonym> {
        const response = await fetch(this.config.url + "/pseudonymize", {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + this.authToken,
            },
            body: JSON.stringify({
                // eslint-disable-next-line camelcase
                encrypted_pseudonym: encryptedPseudonym.asBase64(),
                // eslint-disable-next-line camelcase
                domain_from: domainFrom,
                // eslint-disable-next-line camelcase
                domain_to: domainTo,
                // eslint-disable-next-line camelcase
                session_from: sessionFrom,
                // eslint-disable-next-line camelcase
                session_to: sessionTo,
            } as PseudonymizationRequest),
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
            return err;
        });

        if (response.ok) {
            const data: PseudonymizationResponse = await response.json();
            return EncryptedPseudonym.fromBase64(data.encrypted_pseudonym);
        }
    }

    public async pseudonymizeBatch(
        encryptedPseudonyms: EncryptedPseudonym[],
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        sessionFrom: EncryptionContext,
        sessionTo: EncryptionContext,
    ): Promise<EncryptedPseudonym[]> {
        const response = await fetch(this.config.url + "/pseudonymize", {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + this.authToken,
            },
            body: JSON.stringify({
                // eslint-disable-next-line camelcase
                encrypted_pseudonyms: encryptedPseudonyms.map((p) => p.asBase64()),
                // eslint-disable-next-line camelcase
                domain_from: domainFrom,
                // eslint-disable-next-line camelcase
                domain_to: domainTo,
                // eslint-disable-next-line camelcase
                session_from: sessionFrom,
                // eslint-disable-next-line camelcase
                session_to: sessionTo,
            } as PseudonymizationBatchRequest),
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
            return err;
        });

        if (response.ok) {
            const data: PseudonymizationBatchResponse = await response.json();
            return data.encrypted_pseudonyms.map((p) =>
                EncryptedPseudonym.fromBase64(p),
            );
        }
    }

    public async getSessions(username = null) {
        const response = await fetch(
            `${this.config.url}/sessions/get${username ? "/" + username : ""}`,
            {
                method: "GET",
                mode: "cors",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: "Bearer " + this.authToken,
                },
            },
        ).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
            return err;
        });

        if (response.ok) {
            const data: GetSessionResponse = response.json();
            return data.sessions;
        }
    }

    public getStatus() {
        return this.status;
    }

    public getSessionId() {
        return this.sessionId;
    }

    public getUrl() {
        return this.config.url;
    }

    public getSystemId() {
        return this.config.systemId;
    }
}
