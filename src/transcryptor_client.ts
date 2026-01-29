import {
  AttributeSessionKeyShare,
  EncryptedAttribute,
  EncryptedPseudonym,
  LongEncryptedAttribute,
  LongEncryptedPseudonym,
  EncryptedPEPJSONValue,
  PseudonymSessionKeyShare,
  SessionKeyShares,
} from "@nolai/libpep-wasm";

import {
  PseudonymizationDomain,
  VersionInfo,
  StatusResponse,
  StartSessionResponse,
  SessionResponse,
  EndSessionRequest,
  PseudonymizationRequest,
  PseudonymizationResponse,
  LongPseudonymizationRequest,
  LongPseudonymizationResponse,
  PseudonymizationBatchRequest,
  PseudonymizationBatchResponse,
  LongPseudonymizationBatchRequest,
  LongPseudonymizationBatchResponse,
  RekeyRequest,
  RekeyResponse,
  LongRekeyRequest,
  LongRekeyResponse,
  RekeyBatchRequest,
  RekeyBatchResponse,
  LongRekeyBatchRequest,
  LongRekeyBatchResponse,
  TranscryptionRequest,
  TranscryptionResponse,
  LongTranscryptionRequest,
  LongTranscryptionResponse,
  TranscryptionBatchRequest,
  TranscryptionBatchResponse,
  LongTranscryptionBatchRequest,
  LongTranscryptionBatchResponse,
  JsonTranscryptionRequest,
  JsonTranscryptionResponse,
  JsonTranscryptionBatchRequest,
  JsonTranscryptionBatchResponse,
  EncryptedData,
  LongEncryptedData,
  AnyEncryptedPseudonym,
  AnyEncryptedAttribute,
  AnyEncryptedData,
  isLongEncryptedPseudonym,
  isLongEncryptedAttribute,
  isEncryptedPEPJSONValue,
  isLongEncryptedData,
} from "./messages.js";
import { EncryptionContext, SystemId } from "./sessions.js";
import { PAASConfig, TranscryptorConfig } from "./config.js";
import { Auth } from "./auth.js";
import { PseudonymServiceError } from "./pseudonym_service.js";

/**
 * Enum representing the state of a transcryptor
 */
export enum TranscryptorState {
  UNKNOWN = "unknown",
  ONLINE = "online",
  OFFLINE = "offline",
  ERROR = "error",
}

/**
 * Class representing the status of a transcryptor
 */
export class TranscryptorStatus {
  state: TranscryptorState;
  lastChecked: number;

  constructor(state: TranscryptorState, lastChecked: number) {
    this.state = state;
    this.lastChecked = lastChecked;
  }
}

/**
 * Enum representing the types of errors that can occur in a transcryptor
 */
export enum TranscryptorErrorType {
  AuthError = "AuthError",
  NetworkError = "NetworkError",
  Unauthorized = "Unauthorized",
  NotAllowed = "NotAllowed",
  InvalidSession = "InvalidSession",
  BadRequest = "BadRequest",
  ServerError = "ServerError",
  NoSessionToEnd = "NoSessionToEnd",
  IncompatibleClientVersion = "IncompatibleClientVersion",
  InconsistentSystemName = "InconsistentSystemName",
  InvalidSystemName = "InvalidSystemName",
  InconsistentConfig = "InconsistentConfig",
}

/**
 * Class representing an error that occurred in a transcryptor
 */
export class TranscryptorError extends Error {
  type: TranscryptorErrorType;
  details?: Record<string, string>;

  constructor(
    type: TranscryptorErrorType,
    message: string,
    details?: Record<string, string>,
  ) {
    super(message);
    this.type = type;
    this.details = details;
    this.name = "TranscryptorError";
  }

  static authError(message: string): TranscryptorError {
    return new TranscryptorError(TranscryptorErrorType.AuthError, message);
  }

  static networkError(message: string): TranscryptorError {
    return new TranscryptorError(TranscryptorErrorType.NetworkError, message);
  }

  static unauthorized(): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.Unauthorized,
      "Authentication required",
    );
  }

  static notAllowed(reason: string): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.NotAllowed,
      `Transcryption not allowed: ${reason}`,
    );
  }

  static invalidSession(reason: string): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.InvalidSession,
      `Invalid or expired session: ${reason}`,
    );
  }

  static badRequest(reason: string): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.BadRequest,
      `Bad request: ${reason}`,
    );
  }

  static serverError(reason: string): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.ServerError,
      `Server error: ${reason}`,
    );
  }

  static noSessionToEnd(): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.NoSessionToEnd,
      "No active session to end",
    );
  }

  static incompatibleClientVersion(
    clientVersion: string,
    serverVersion: string,
    minSupportedVersion: string,
  ): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.IncompatibleClientVersion,
      `Client version ${clientVersion} is incompatible with server version ${serverVersion} (min. supported version ${minSupportedVersion})`,
      { clientVersion, serverVersion, minSupportedVersion },
    );
  }

  static inconsistentSystemName(
    configuredName: string,
    respondedName: string,
  ): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.InconsistentSystemName,
      `Inconsistent system name (configured: ${configuredName}, responded: ${respondedName})`,
      { configuredName, respondedName },
    );
  }

  static invalidSystemName(name: string): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.InvalidSystemName,
      `Invalid system name (${name})`,
      { name },
    );
  }

  static inconsistentConfig(
    configuredUrl: string,
    respondedUrl: string,
  ): TranscryptorError {
    return new TranscryptorError(
      TranscryptorErrorType.InconsistentConfig,
      `Inconsistent configuration (configured: ${configuredUrl}, responded: ${respondedUrl})`,
      { configuredUrl, respondedUrl },
    );
  }
}

/**
 * Interface for error responses from the server
 */
interface ErrorResponse {
  error: string;
}

/**
 * A client that communicates with a single Transcryptor.
 */
export class TranscryptorClient {
  config: TranscryptorConfig;
  sessionId: EncryptionContext | null = null;
  keyShares: SessionKeyShares | null = null;
  status: TranscryptorStatus;
  private auth: Auth;
  private apiBasePath = ""; // This should match paas_api::paths::API_BASE in Rust

  /**
   * Private constructor - use factory methods instead
   */
  private constructor(config: TranscryptorConfig, auth: Auth) {
    this.config = config;
    this.auth = auth;
    this.status = new TranscryptorStatus(TranscryptorState.UNKNOWN, Date.now());
  }

  /**
   * Create and initialize a new TranscryptorClient
   */
  static async new(
    config: TranscryptorConfig,
    auth: Auth,
  ): Promise<TranscryptorClient> {
    const client = new TranscryptorClient(config, auth);
    await client.checkStatus();
    return client;
  }

  /**
   * Restore a TranscryptorClient from saved state
   */
  static async restore(
    config: TranscryptorConfig,
    auth: Auth,
    sessionId: EncryptionContext,
    keyShares: SessionKeyShares,
  ): Promise<TranscryptorClient> {
    const client = new TranscryptorClient(config, auth);
    client.sessionId = sessionId;
    client.keyShares = keyShares;
    await client.checkStatus();
    return client;
  }

  /**
   * Get the full URL for an API endpoint
   */
  private makeUrl(path: string): string {
    return `${this.config.url.replace(/\/$/, "")}${this.apiBasePath}${path}`;
  }

  /**
   * Process an API response, handling errors
   */
  private async processResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      const status = response.status;
      let errorMessage: string;

      try {
        const body = await response.text();
        try {
          const errorResponse = JSON.parse(body) as ErrorResponse;
          errorMessage = errorResponse.error || body;
        } catch {
          errorMessage = body;
        }
      } catch {
        errorMessage = `HTTP error ${status}`;
      }

      switch (status) {
        case 401:
          throw TranscryptorError.unauthorized();
        case 403:
          throw TranscryptorError.notAllowed(errorMessage);
        case 404:
          throw TranscryptorError.invalidSession(errorMessage);
        case 400:
          throw TranscryptorError.badRequest(errorMessage);
        case 500:
        case 501:
        case 502:
        case 503:
        case 504:
          throw TranscryptorError.serverError(errorMessage);
        default:
          throw TranscryptorError.networkError(
            `Unexpected HTTP status ${status}: ${errorMessage}`,
          );
      }
    }

    try {
      return (await response.json()) as T;
    } catch (error) {
      throw TranscryptorError.networkError(
        `Failed to parse JSON response: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Check the status of the transcryptor
   */
  async checkStatus(): Promise<void> {
    try {
      const response = await fetch(this.makeUrl("/status"));

      if (!response.ok) {
        this.status = new TranscryptorStatus(
          response.status === 404
            ? TranscryptorState.OFFLINE
            : TranscryptorState.ERROR,
          Date.now(),
        );
        return;
      }

      const status = await this.processResponse<StatusResponse>(response);
      this.status = new TranscryptorStatus(
        TranscryptorState.ONLINE,
        Date.now(),
      );

      // Check system ID match
      if (status.system_id !== this.config.system_id) {
        throw TranscryptorError.inconsistentSystemName(
          this.config.system_id,
          status.system_id,
        );
      }

      // Check version compatibility
      const clientVersion = {
        // eslint-disable-next-line camelcase
        protocol_version: "0.10.1",
        // eslint-disable-next-line camelcase
        min_supported_version: "0.10.0",
      } as VersionInfo;

      if (!this.isCompatibleVersion(status.version_info, clientVersion)) {
        throw TranscryptorError.incompatibleClientVersion(
          clientVersion.protocol_version,
          status.version_info.protocol_version,
          status.version_info.min_supported_version,
        );
      }
    } catch (error) {
      if (error instanceof TranscryptorError) {
        this.status = new TranscryptorStatus(
          TranscryptorState.ERROR,
          Date.now(),
        );
        throw error;
      }

      this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
      throw TranscryptorError.networkError(
        `Failed to check status: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Check if client and server versions are compatible
   */
  private isCompatibleVersion(
    serverVersion: VersionInfo,
    clientVersion: VersionInfo,
  ): boolean {
    const compare = (v1: string, v2: string): number => {
      const p1 = v1.split(".").map(Number);
      const p2 = v2.split(".").map(Number);

      for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
        const diff = (p1[i] || 0) - (p2[i] || 0);
        if (diff !== 0) return diff;
      }
      return 0;
    };

    return (
      compare(
        serverVersion.protocol_version,
        clientVersion.min_supported_version,
      ) >= 0 &&
      compare(
        clientVersion.protocol_version,
        serverVersion.min_supported_version,
      ) >= 0
    );
  }

  /**
   * Verify the config of the system
   */
  async checkConfig(clientsideConfig: PAASConfig): Promise<any> {
    try {
      const token = await this.auth.token();
      const headers = {
        Authorization: `Bearer ${token}`,
      };

      const response = await fetch(this.makeUrl("/config"), { headers });
      const config = await this.processResponse<PAASConfig>(response);

      // Find this transcryptor in the config
      const transcryptorConfig = config.transcryptors.find(
        (tc) => tc.system_id === this.config.system_id,
      );

      if (!transcryptorConfig) {
        throw TranscryptorError.invalidSystemName(this.config.system_id);
      }

      // Check URL consistency
      if (transcryptorConfig.url !== this.config.url) {
        throw TranscryptorError.inconsistentConfig(
          this.config.url,
          transcryptorConfig.url,
        );
      }

      if (
        clientsideConfig.blinded_global_keys.attribute !==
          config.blinded_global_keys.attribute ||
        clientsideConfig.blinded_global_keys.pseudonym !==
          config.blinded_global_keys.pseudonym ||
        clientsideConfig.global_public_keys.attribute !==
          config.global_public_keys.attribute ||
        clientsideConfig.global_public_keys.pseudonym !==
          config.global_public_keys.pseudonym
      ) {
        throw PseudonymServiceError.inconsistentConfig(
          transcryptorConfig.system_id,
        );
      }

      return config;
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to check config: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Start a new session with the transcryptor
   */
  async startSession(): Promise<{
    sessionId: EncryptionContext;
    keyShares: SessionKeyShares;
  }> {
    try {
      const token = await this.auth.token();
      const response = await fetch(this.makeUrl("/sessions/start"), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      const sessionData =
        await this.processResponse<StartSessionResponse>(response);

      this.sessionId = sessionData.session_id;
      this.keyShares = new SessionKeyShares(
        PseudonymSessionKeyShare.fromHex(
          sessionData.session_key_shares.pseudonym,
        ),
        AttributeSessionKeyShare.fromHex(
          sessionData.session_key_shares.attribute,
        ),
      );

      return {
        sessionId: sessionData.session_id,
        keyShares: this.keyShares,
      };
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to start session: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Get all sessions for the current user
   */
  async getSessions(): Promise<EncryptionContext[]> {
    try {
      const token = await this.auth.token();
      const response = await fetch(this.makeUrl("/sessions/get"), {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const sessionData = await this.processResponse<SessionResponse>(response);
      return sessionData.sessions;
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to get sessions: ${(error as Error).message}`,
      );
    }
  }

  /**
   * End a session
   */
  async endSession(): Promise<void> {
    if (!this.sessionId) {
      throw TranscryptorError.noSessionToEnd();
    }

    try {
      const request: EndSessionRequest = {
        // eslint-disable-next-line camelcase
        session_id: this.sessionId,
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl("/sessions/end"), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      await this.processResponse<void>(response);

      this.sessionId = null;
      this.keyShares = null;
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to end session: ${(error as Error).message}`,
      );
    }
  }

  // ===========================================================================
  // Pseudonymization Methods
  // ===========================================================================

  /**
   * Pseudonymize an encrypted pseudonym.
   * Polymorphic: accepts both EncryptedPseudonym and LongEncryptedPseudonym,
   * automatically routes to the correct endpoint, and returns the same type.
   */
  async pseudonymize<T extends AnyEncryptedPseudonym>(
    encryptedPseudonym: T,
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<T> {
    try {
      const isLong = isLongEncryptedPseudonym(encryptedPseudonym);
      const endpoint = isLong ? "/long/pseudonymize" : "/pseudonymize";

      const request: PseudonymizationRequest | LongPseudonymizationRequest = {
        // eslint-disable-next-line camelcase
        encrypted_pseudonym: isLong
          ? (encryptedPseudonym as LongEncryptedPseudonym).serialize()
          : (encryptedPseudonym as EncryptedPseudonym).toBase64(),
        // eslint-disable-next-line camelcase
        domain_from: domainFrom,
        // eslint-disable-next-line camelcase
        domain_to: domainTo,
        // eslint-disable-next-line camelcase
        session_from: sessionFrom,
        // eslint-disable-next-line camelcase
        session_to: sessionTo,
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl(endpoint), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data = await this.processResponse<
        PseudonymizationResponse | LongPseudonymizationResponse
      >(response);

      if (isLong) {
        return LongEncryptedPseudonym.deserialize(
          data.encrypted_pseudonym,
        ) as T;
      }
      return EncryptedPseudonym.fromBase64(data.encrypted_pseudonym) as T;
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to pseudonymize: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Pseudonymize a batch of encrypted pseudonyms.
   * Polymorphic: accepts both EncryptedPseudonym[] and LongEncryptedPseudonym[],
   * automatically routes to the correct endpoint, and returns the same type.
   */
  async pseudonymizeBatch<T extends AnyEncryptedPseudonym>(
    encryptedPseudonyms: T[],
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<T[]> {
    try {
      // Determine type from first element (all must be same type)
      const isLong =
        encryptedPseudonyms.length > 0 &&
        isLongEncryptedPseudonym(encryptedPseudonyms[0]);
      const endpoint = isLong
        ? "/long/pseudonymize/batch"
        : "/pseudonymize/batch";

      const request:
        | PseudonymizationBatchRequest
        | LongPseudonymizationBatchRequest = {
        // eslint-disable-next-line camelcase
        encrypted_pseudonyms: encryptedPseudonyms.map((p) =>
          isLong
            ? (p as LongEncryptedPseudonym).serialize()
            : (p as EncryptedPseudonym).toBase64(),
        ),
        // eslint-disable-next-line camelcase
        domain_from: domainFrom,
        // eslint-disable-next-line camelcase
        domain_to: domainTo,
        // eslint-disable-next-line camelcase
        session_from: sessionFrom,
        // eslint-disable-next-line camelcase
        session_to: sessionTo,
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl(endpoint), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data = await this.processResponse<
        PseudonymizationBatchResponse | LongPseudonymizationBatchResponse
      >(response);

      if (isLong) {
        return data.encrypted_pseudonyms.map(
          (p) => LongEncryptedPseudonym.deserialize(p) as T,
        );
      }
      return data.encrypted_pseudonyms.map(
        (p) => EncryptedPseudonym.fromBase64(p) as T,
      );
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to pseudonymize batch: ${(error as Error).message}`,
      );
    }
  }

  // ===========================================================================
  // Rekey Methods
  // ===========================================================================

  /**
   * Rekey an encrypted attribute.
   * Polymorphic: accepts both EncryptedAttribute and LongEncryptedAttribute,
   * automatically routes to the correct endpoint, and returns the same type.
   */
  async rekey<T extends AnyEncryptedAttribute>(
    encryptedAttribute: T,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<T> {
    try {
      const isLong = isLongEncryptedAttribute(encryptedAttribute);
      const endpoint = isLong ? "/long/rekey" : "/rekey";

      const request: RekeyRequest | LongRekeyRequest = {
        // eslint-disable-next-line camelcase
        encrypted_attribute: isLong
          ? (encryptedAttribute as LongEncryptedAttribute).serialize()
          : (encryptedAttribute as EncryptedAttribute).toBase64(),
        // eslint-disable-next-line camelcase
        session_from: sessionFrom,
        // eslint-disable-next-line camelcase
        session_to: sessionTo,
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl(endpoint), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data = await this.processResponse<
        RekeyResponse | LongRekeyResponse
      >(response);

      if (isLong) {
        return LongEncryptedAttribute.deserialize(
          data.encrypted_attribute,
        ) as T;
      }
      return EncryptedAttribute.fromBase64(data.encrypted_attribute) as T;
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to rekey: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Rekey a batch of encrypted attributes.
   * Polymorphic: accepts both EncryptedAttribute[] and LongEncryptedAttribute[],
   * automatically routes to the correct endpoint, and returns the same type.
   */
  async rekeyBatch<T extends AnyEncryptedAttribute>(
    encryptedAttributes: T[],
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<T[]> {
    try {
      // Determine type from first element (all must be same type)
      const isLong =
        encryptedAttributes.length > 0 &&
        isLongEncryptedAttribute(encryptedAttributes[0]);
      const endpoint = isLong ? "/long/rekey/batch" : "/rekey/batch";

      const request: RekeyBatchRequest | LongRekeyBatchRequest = {
        // eslint-disable-next-line camelcase
        encrypted_attributes: encryptedAttributes.map((a) =>
          isLong
            ? (a as LongEncryptedAttribute).serialize()
            : (a as EncryptedAttribute).toBase64(),
        ),
        // eslint-disable-next-line camelcase
        session_from: sessionFrom,
        // eslint-disable-next-line camelcase
        session_to: sessionTo,
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl(endpoint), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data = await this.processResponse<
        RekeyBatchResponse | LongRekeyBatchResponse
      >(response);

      if (isLong) {
        return data.encrypted_attributes.map(
          (a) => LongEncryptedAttribute.deserialize(a) as T,
        );
      }
      return data.encrypted_attributes.map(
        (a) => EncryptedAttribute.fromBase64(a) as T,
      );
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to rekey batch: ${(error as Error).message}`,
      );
    }
  }

  // ===========================================================================
  // Transcryption Methods
  // ===========================================================================

  /**
   * Transcrypt a single encrypted data item.
   * Polymorphic: accepts EncryptedData, LongEncryptedData, or EncryptedPEPJSONValue,
   * automatically routes to the correct endpoint, and returns the same type.
   */
  async transcrypt<T extends AnyEncryptedData>(
    encrypted: T,
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<T> {
    try {
      // Determine endpoint and serialize based on data type
      if (isEncryptedPEPJSONValue(encrypted)) {
        const request: JsonTranscryptionRequest = {
          encrypted: encrypted.toJSON(),
          // eslint-disable-next-line camelcase
          domain_from: domainFrom,
          // eslint-disable-next-line camelcase
          domain_to: domainTo,
          // eslint-disable-next-line camelcase
          session_from: sessionFrom,
          // eslint-disable-next-line camelcase
          session_to: sessionTo,
        };

        const token = await this.auth.token();
        const response = await fetch(this.makeUrl("/json/transcrypt"), {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(request),
        });

        const data =
          await this.processResponse<JsonTranscryptionResponse>(response);
        return EncryptedPEPJSONValue.fromJSON(data.encrypted) as T;
      } else if (isLongEncryptedData(encrypted)) {
        const d = encrypted as LongEncryptedData;
        const request: LongTranscryptionRequest = {
          encrypted: [
            d.encrypted_pseudonym.map((p) => p.serialize()),
            d.encrypted_attribute.map((a) => a.serialize()),
          ],
          // eslint-disable-next-line camelcase
          domain_from: domainFrom,
          // eslint-disable-next-line camelcase
          domain_to: domainTo,
          // eslint-disable-next-line camelcase
          session_from: sessionFrom,
          // eslint-disable-next-line camelcase
          session_to: sessionTo,
        };

        const token = await this.auth.token();
        const response = await fetch(this.makeUrl("/long/transcrypt"), {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(request),
        });

        const data =
          await this.processResponse<LongTranscryptionResponse>(response);
        return {
          // eslint-disable-next-line camelcase
          encrypted_pseudonym: data.encrypted[0].map((p) =>
            LongEncryptedPseudonym.deserialize(p),
          ),
          // eslint-disable-next-line camelcase
          encrypted_attribute: data.encrypted[1].map((a) =>
            LongEncryptedAttribute.deserialize(a),
          ),
        } as T;
      } else {
        const d = encrypted as EncryptedData;
        const request: TranscryptionRequest = {
          encrypted: [
            d.encrypted_pseudonym.map((p) => p.toBase64()),
            d.encrypted_attribute.map((a) => a.toBase64()),
          ],
          // eslint-disable-next-line camelcase
          domain_from: domainFrom,
          // eslint-disable-next-line camelcase
          domain_to: domainTo,
          // eslint-disable-next-line camelcase
          session_from: sessionFrom,
          // eslint-disable-next-line camelcase
          session_to: sessionTo,
        };

        const token = await this.auth.token();
        const response = await fetch(this.makeUrl("/transcrypt"), {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(request),
        });

        const data =
          await this.processResponse<TranscryptionResponse>(response);
        return {
          // eslint-disable-next-line camelcase
          encrypted_pseudonym: data.encrypted[0].map((p) =>
            EncryptedPseudonym.fromBase64(p),
          ),
          // eslint-disable-next-line camelcase
          encrypted_attribute: data.encrypted[1].map((a) =>
            EncryptedAttribute.fromBase64(a),
          ),
        } as T;
      }
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to transcrypt: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Transcrypt a batch of encrypted data items.
   * Polymorphic: accepts EncryptedData[], LongEncryptedData[], or EncryptedPEPJSONValue[],
   * automatically routes to the correct endpoint, and returns the same type.
   */
  async transcryptBatch<T extends AnyEncryptedData>(
    encrypted: T[],
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<T[]> {
    try {
      if (encrypted.length === 0) {
        return [];
      }

      // Determine endpoint and serialize based on first item's type
      if (isEncryptedPEPJSONValue(encrypted[0])) {
        const request: JsonTranscryptionBatchRequest = {
          encrypted: (encrypted as EncryptedPEPJSONValue[]).map((e) =>
            e.toJSON(),
          ),
          // eslint-disable-next-line camelcase
          domain_from: domainFrom,
          // eslint-disable-next-line camelcase
          domain_to: domainTo,
          // eslint-disable-next-line camelcase
          session_from: sessionFrom,
          // eslint-disable-next-line camelcase
          session_to: sessionTo,
        };

        const token = await this.auth.token();
        const response = await fetch(this.makeUrl("/json/transcrypt/batch"), {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(request),
        });

        const data =
          await this.processResponse<JsonTranscryptionBatchResponse>(response);
        return data.encrypted.map(
          (e) => EncryptedPEPJSONValue.fromJSON(e) as T,
        );
      } else if (isLongEncryptedData(encrypted[0])) {
        const request: LongTranscryptionBatchRequest = {
          encrypted: (encrypted as LongEncryptedData[]).map((e) => [
            e.encrypted_pseudonym.map((p) => p.serialize()),
            e.encrypted_attribute.map((a) => a.serialize()),
          ]),
          // eslint-disable-next-line camelcase
          domain_from: domainFrom,
          // eslint-disable-next-line camelcase
          domain_to: domainTo,
          // eslint-disable-next-line camelcase
          session_from: sessionFrom,
          // eslint-disable-next-line camelcase
          session_to: sessionTo,
        };

        const token = await this.auth.token();
        const response = await fetch(this.makeUrl("/long/transcrypt/batch"), {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(request),
        });

        const data =
          await this.processResponse<LongTranscryptionBatchResponse>(response);
        return data.encrypted.map(
          (e) =>
            ({
              // eslint-disable-next-line camelcase
              encrypted_pseudonym: e[0].map((p) =>
                LongEncryptedPseudonym.deserialize(p),
              ),
              // eslint-disable-next-line camelcase
              encrypted_attribute: e[1].map((a) =>
                LongEncryptedAttribute.deserialize(a),
              ),
            }) as T,
        );
      } else {
        const request: TranscryptionBatchRequest = {
          encrypted: (encrypted as EncryptedData[]).map((e) => [
            e.encrypted_pseudonym.map((p) => p.toBase64()),
            e.encrypted_attribute.map((a) => a.toBase64()),
          ]),
          // eslint-disable-next-line camelcase
          domain_from: domainFrom,
          // eslint-disable-next-line camelcase
          domain_to: domainTo,
          // eslint-disable-next-line camelcase
          session_from: sessionFrom,
          // eslint-disable-next-line camelcase
          session_to: sessionTo,
        };

        const token = await this.auth.token();
        const response = await fetch(this.makeUrl("/transcrypt/batch"), {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(request),
        });

        const data =
          await this.processResponse<TranscryptionBatchResponse>(response);
        return data.encrypted.map(
          (e) =>
            ({
              // eslint-disable-next-line camelcase
              encrypted_pseudonym: e[0].map((p) =>
                EncryptedPseudonym.fromBase64(p),
              ),
              // eslint-disable-next-line camelcase
              encrypted_attribute: e[1].map((a) =>
                EncryptedAttribute.fromBase64(a),
              ),
            }) as T,
        );
      }
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to transcrypt batch: ${(error as Error).message}`,
      );
    }
  }

  // ===========================================================================
  // Getter Methods
  // ===========================================================================

  /**
   * Get the system ID
   */
  getSystemId(): SystemId {
    return this.config.system_id;
  }

  /**
   * Get the session ID
   */
  getSessionId(): EncryptionContext | null {
    return this.sessionId;
  }

  /**
   * Get the key share
   */
  getKeyShares(): SessionKeyShares | null {
    return this.keyShares;
  }

  /**
   * Get the status of the transcryptor
   */
  getStatus(): TranscryptorStatus {
    return this.status;
  }
}
