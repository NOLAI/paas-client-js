import {
  EncryptedDataPoint,
  EncryptedPseudonym,
  SessionKeyShare,
} from "@nolai/libpep-wasm";

import { PseudonymizationDomain, EncryptedEntityData } from "./messages.js";
import { EncryptionContext, SystemId } from "./sessions.js";
import { PAASConfig, TranscryptorConfig } from "./config.js";
import { Auth } from "./auth.js";
import {
  VersionInfo,
  StatusResponse,
  StartSessionResponse,
  SessionResponse,
  EndSessionRequest,
  PseudonymizationRequest,
  PseudonymizationResponse,
  PseudonymizationBatchRequest,
  PseudonymizationBatchResponse,
  RekeyRequest,
  RekeyResponse,
  RekeyBatchRequest,
  RekeyBatchResponse,
  TranscryptionRequest,
  TranscryptionResponse,
} from "./messages.js";
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
  keyShare: SessionKeyShare | null = null;
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
    keyShare: SessionKeyShare,
  ): Promise<TranscryptorClient> {
    const client = new TranscryptorClient(config, auth);
    client.sessionId = sessionId;
    client.keyShare = keyShare;
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
        protocol_version: "0.3.0",
        // eslint-disable-next-line camelcase
        min_supported_version: "0.3.0",
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
    // Compare semantic versions - this is a simplified implementation
    return (
      serverVersion.protocol_version >= clientVersion.min_supported_version &&
      clientVersion.protocol_version >= serverVersion.min_supported_version
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
        clientsideConfig.blinded_global_secret_key !==
          config.blinded_global_secret_key ||
        clientsideConfig.global_public_key !== config.global_public_key
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
    keyShare: SessionKeyShare;
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
      this.keyShare = SessionKeyShare.fromHex(sessionData.key_share);

      return {
        sessionId: sessionData.session_id,
        keyShare: this.keyShare,
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
      this.keyShare = null;
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to end session: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Pseudonymize an encrypted pseudonym
   */
  async pseudonymize(
    encryptedPseudonym: EncryptedPseudonym,
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<EncryptedPseudonym> {
    try {
      const request: PseudonymizationRequest = {
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
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl("/pseudonymize"), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data =
        await this.processResponse<PseudonymizationResponse>(response);
      return EncryptedPseudonym.fromBase64(data.encrypted_pseudonym);
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
   * Pseudonymize a batch of encrypted pseudonyms
   */
  async pseudonymizeBatch(
    encryptedPseudonyms: EncryptedPseudonym[],
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<EncryptedPseudonym[]> {
    try {
      const request: PseudonymizationBatchRequest = {
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
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl("/pseudonymize/batch"), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data =
        await this.processResponse<PseudonymizationBatchResponse>(response);
      return data.encrypted_pseudonyms.map((p) =>
        EncryptedPseudonym.fromBase64(p),
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

  /**
   * Rekey an encrypted data point
   */
  async rekey(
    encryptedData: EncryptedDataPoint,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<EncryptedDataPoint> {
    try {
      const request: RekeyRequest = {
        // eslint-disable-next-line camelcase
        encrypted_data: encryptedData.asBase64(),
        // eslint-disable-next-line camelcase
        session_from: sessionFrom,
        // eslint-disable-next-line camelcase
        session_to: sessionTo,
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl("/rekey"), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data = await this.processResponse<RekeyResponse>(response);
      return EncryptedDataPoint.fromBase64(data.encrypted_data);
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
   * Rekey a batch of encrypted data points
   */
  async rekeyBatch(
    encryptedData: EncryptedDataPoint[],
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<EncryptedDataPoint[]> {
    try {
      const request: RekeyBatchRequest = {
        // eslint-disable-next-line camelcase
        encrypted_data: encryptedData.map((d) => d.asBase64()),
        // eslint-disable-next-line camelcase
        session_from: sessionFrom,
        // eslint-disable-next-line camelcase
        session_to: sessionTo,
      };

      const token = await this.auth.token();
      const response = await fetch(this.makeUrl("/rekey/batch"), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data = await this.processResponse<RekeyBatchResponse>(response);
      return data.encrypted_data.map((d) => EncryptedDataPoint.fromBase64(d));
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw error;
      }
      throw TranscryptorError.networkError(
        `Failed to rekey batch: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Transcrypt data consisting of multiple pseudonyms and data points
   */
  async transcrypt(
    encrypted: EncryptedEntityData[],
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
    sessionFrom: EncryptionContext,
    sessionTo: EncryptionContext,
  ): Promise<EncryptedEntityData[]> {
    try {
      const request: TranscryptionRequest = {
        encrypted: encrypted.map((e) => [
          e.encrypted_pseudonym.map((pseu) => pseu.asBase64()),
          e.encrypted_data_points.map((dp) => dp.asBase64()),
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
      const response = await fetch(this.makeUrl("/transcrypt"), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      const data = await this.processResponse<TranscryptionResponse>(response);

      return data.encrypted.map((e) => ({
        // eslint-disable-next-line camelcase
        encrypted_pseudonym: e[0].map((pseu) =>
          EncryptedPseudonym.fromBase64(pseu),
        ),
        // eslint-disable-next-line camelcase
        encrypted_data_points: e[1].map((dp) =>
          EncryptedDataPoint.fromBase64(dp),
        ),
      }));
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
  getKeyShare(): SessionKeyShare | null {
    return this.keyShare;
  }

  /**
   * Get the status of the transcryptor
   */
  getStatus(): TranscryptorStatus {
    return this.status;
  }
}
