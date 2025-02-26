import {
  BlindedGlobalSecretKey,
  DataPoint,
  EncryptedDataPoint,
  EncryptedPseudonym,
  PEPClient,
  Pseudonym, SessionKeyPair,
  SessionKeyShare,
} from "@nolai/libpep-wasm";

import { PseudonymizationDomain, EncryptedEntityData } from "./messages.js";
import { TranscryptorClient, TranscryptorError } from "./transcryptor_client.js";
import { EncryptionContext, EncryptionContexts, SystemId } from "./sessions.js";
import {PAASConfig} from "./config.js";
import { SystemAuths } from "./auth.js";

/**
 * Types of errors that can occur in the PseudonymService
 */
export enum PseudonymServiceErrorType {
  TranscryptorError = "TranscryptorError",
  MissingAuth = "MissingAuth",
  MissingSession = "MissingSession",
  MissingSessionKeyShare = "MissingSessionKeyShare",
  UninitializedPEPClient = "UninitializedPEPClient",
  UninitializedTranscryptor = "UninitializedTranscryptor",
  InconsistentConfig = "InconsistentConfig"
}

/**
 * Error class for PseudonymService errors
 */
export class PseudonymServiceError extends Error {
  type: PseudonymServiceErrorType;
  details?: Record<string, string>;
  cause?: Error;

  constructor(type: PseudonymServiceErrorType, message: string, cause?: Error, details?: Record<string, string>) {
    super(message);
    this.type = type;
    this.cause = cause;
    this.details = details;
    this.name = "PseudonymServiceError";
  }

  static transcryptorError(error: TranscryptorError): PseudonymServiceError {
    return new PseudonymServiceError(
        PseudonymServiceErrorType.TranscryptorError,
        error.message,
        error
    );
  }

  static missingAuth(systemId: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
        PseudonymServiceErrorType.MissingAuth,
        `No auth found for system ${systemId}`,
        undefined,
        { systemId }
    );
  }

  static missingSession(systemId: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
        PseudonymServiceErrorType.MissingSession,
        `No session found for system ${systemId}`,
        undefined,
        { systemId }
    );
  }

  static missingSessionKeyShare(systemId: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
        PseudonymServiceErrorType.MissingSessionKeyShare,
        `No session key share found for system ${systemId}`,
        undefined,
        { systemId }
    );
  }

  static uninitializedPEPClient(): PseudonymServiceError {
    return new PseudonymServiceError(
        PseudonymServiceErrorType.UninitializedPEPClient,
        "PEP crypto client not initialized"
    );
  }

  static uninitializedTranscryptor(): PseudonymServiceError {
    return new PseudonymServiceError(
        PseudonymServiceErrorType.UninitializedTranscryptor,
        "Transcryptor does not have session"
    );
  }

  static inconsistentConfig(system: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
        PseudonymServiceErrorType.InconsistentConfig,
        `Inconsistent config received from ${system}`,
        undefined,
        { system }
    );
  }
}

/**
 * Information needed to store and restore session key shares
 */
export interface SessionKeyShares {
  [systemId: string]: SessionKeyShare; // SessionKeyShare hex string
}

/**
 * Information needed to dump and restore service state
 */
export interface PseudonymServiceDump {
  sessions: EncryptionContexts;
  sessionKeys: SessionKeyPair;
  sessionKeyShares: SessionKeyShares;
}

/**
 * Service for pseudonymizing data across multiple transcryptors
 */
export class PseudonymService {
  private transcryptors: TranscryptorClient[] = [];
  private pepCryptoClient: PEPClient | null = null;
  private config: PAASConfig;

  /**
   * Create a new PseudonymService
   */
  private constructor(config: PAASConfig) {
    this.config = config;
  }

  /**
   * Initialize the PseudonymService with authentication tokens
   */
  public static async new(
      config: PAASConfig,
      auths: SystemAuths
  ): Promise<PseudonymService> {
    const service = new PseudonymService(config);

    // Create all transcryptors
    const transcryptorPromises = config.transcryptors.map(async (tc) => {
      const auth = auths.get(tc.systemId);
      if (!auth) {
        throw PseudonymServiceError.missingAuth(tc.systemId);
      }

      try {
        const transcryptor = await TranscryptorClient.new(tc, auth);

        // Check if the config is consistent with the reported config
        // Fails if the configs are inconsistent
        await transcryptor.checkConfig(config);

        return transcryptor;
      } catch (error) {
        if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        }
        throw error;
      }
    });

    service.transcryptors = await Promise.all(transcryptorPromises);
    return service;
  }

  /**
   * Restore a PseudonymService from a saved state
   */
  public static async restore(
      config: PAASConfig,
      auths: SystemAuths,
      sessionIds: EncryptionContexts,
      sessionKeyShares: SessionKeyShares,
      sessionKeys: SessionKeyPair
  ): Promise<PseudonymService> {

    const service = new PseudonymService(config);

    // Restore all transcryptors
    const transcryptorPromises = config.transcryptors.map(async (tc) => {
      const auth = auths.get(tc.systemId);
      if (!auth) {
        throw PseudonymServiceError.missingAuth(tc.systemId);
      }

      const sessionId = sessionIds.get(tc.systemId);
      if (!sessionId) {
        throw PseudonymServiceError.missingSession(tc.systemId);
      }

      const keyShare = sessionKeyShares[tc.systemId];
      if (!keyShare) {
        throw PseudonymServiceError.missingSessionKeyShare(tc.systemId);
      }

      try {
        return await TranscryptorClient.restore(
            tc,
            auth,
            sessionId,
            keyShare
        );
      } catch (error) {
        if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        }
        throw error;
      }
    });

    service.transcryptors = await Promise.all(transcryptorPromises);

    // Restore PEP client
    service.pepCryptoClient = PEPClient.restore(sessionKeys);

    return service;
  }

  /**
   * Save the current state of the PseudonymService
   */
  public dump(): PseudonymServiceDump {
    if (!this.pepCryptoClient) {
      throw PseudonymServiceError.uninitializedPEPClient();
    }
    const sessions = this.getCurrentSessions();

    // Get session keys from PEP client
    const sessionKeys = this.pepCryptoClient.dump();

    // Get session key shares from transcryptors
    const sessionKeyShares: SessionKeyShares = {};
    for (const transcryptor of this.transcryptors) {
      const keyShare = transcryptor.getKeyShare();
      if (keyShare) {
        sessionKeyShares[transcryptor.getSystemId()] = keyShare;
      }
    }

    return {
      sessions,
      sessionKeys,
      sessionKeyShares
    };
  }

  /**
   * Initialize the PseudonymService by starting sessions with all transcryptors
   */
  public async init(): Promise<void> {
    const keyShares: SessionKeyShare[] = [];

    // Start sessions with all transcryptors
    for (const transcryptor of this.transcryptors) {
      try {
        const { keyShare } = await transcryptor.startSession();
        keyShares.push(keyShare);
      } catch (error) {
        if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        }
        throw error;
      }
    }

    // Initialize the PEP crypto client
    this.pepCryptoClient = new PEPClient(
        BlindedGlobalSecretKey.fromHex(this.config.blinded_global_secret_key),
        keyShares
    );
  }

  /**
   * End all sessions
   */
  public async end(): Promise<void> {
    // End sessions with all transcryptors
    const promises = this.transcryptors.map(async (transcryptor) => {
      try {
        await transcryptor.endSession();
      } catch (error) {
        if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        }
        throw error;
      }
    });

    await Promise.all(promises);
  }

  /**
   * Refresh a transcryptor's session
   */
  public async refreshSession(transcryptorIndex: number): Promise<void> {
    if (transcryptorIndex < 0 || transcryptorIndex >= this.transcryptors.length) {
      throw new Error(`Invalid transcryptor index: ${transcryptorIndex}`);
    }

    const transcryptor = this.transcryptors[transcryptorIndex];
    const oldKeyShare = transcryptor.getKeyShare();

    try {
      // Start a new session for the transcryptor
      const { keyShare: newKeyShare } = await transcryptor.startSession();

      // Update the session key in the PEP crypto client if it exists
      if (oldKeyShare && this.pepCryptoClient) {
        this.pepCryptoClient.updateSessionSecretKey(oldKeyShare, newKeyShare);
      } else {
        // Otherwise initialize all sessions
        await this.init();
      }
    } catch (error) {
      if (error instanceof TranscryptorError) {
        throw PseudonymServiceError.transcryptorError(error);
      }
      throw error;
    }
  }

  /**
   * Pseudonymize an encrypted pseudonym through all transcryptors
   */
  public async pseudonymize(
      encryptedPseudonym: EncryptedPseudonym,
      sessionsFrom: EncryptionContexts,
      domainFrom: PseudonymizationDomain,
      domainTo: PseudonymizationDomain
  ): Promise<EncryptedPseudonym> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    // Pseudonymize through each transcryptor
    for (let i = 0; i < this.transcryptors.length; i++) {
      const transcryptor = this.transcryptors[i];
      const systemId = transcryptor.getSystemId();

      const sessionFrom = sessionsFrom.get(systemId);
      if (!sessionFrom) {
        throw PseudonymServiceError.missingSession(systemId);
      }

      const sessionTo = transcryptor.getSessionId();
      if (!sessionTo) {
        throw PseudonymServiceError.uninitializedTranscryptor();
      }

      try {
        encryptedPseudonym = await transcryptor.pseudonymize(
            encryptedPseudonym,
            domainFrom,
            domainTo,
            sessionFrom,
            sessionTo
        );
      } catch (error) {
        if (error instanceof TranscryptorError &&
            error.type === 'InvalidSession') {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          encryptedPseudonym = await transcryptor.pseudonymize(
              encryptedPseudonym,
              domainFrom,
              domainTo,
              sessionFrom,
              sessionTo
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return encryptedPseudonym;
  }

  /**
   * Pseudonymize a batch of encrypted pseudonyms through all transcryptors
   */
  public async pseudonymizeBatch(
      encryptedPseudonyms: EncryptedPseudonym[],
      sessionsFrom: EncryptionContexts,
      domainFrom: PseudonymizationDomain,
      domainTo: PseudonymizationDomain
  ): Promise<EncryptedPseudonym[]> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    // Pseudonymize through each transcryptor
    for (let i = 0; i < this.transcryptors.length; i++) {
      const transcryptor = this.transcryptors[i];
      const systemId = transcryptor.getSystemId();

      const sessionFrom = sessionsFrom.get(systemId);
      if (!sessionFrom) {
        throw PseudonymServiceError.missingSession(systemId);
      }

      const sessionTo = transcryptor.getSessionId();
      if (!sessionTo) {
        throw PseudonymServiceError.uninitializedTranscryptor();
      }

      try {
        encryptedPseudonyms = await transcryptor.pseudonymizeBatch(
            encryptedPseudonyms,
            domainFrom,
            domainTo,
            sessionFrom,
            sessionTo
        );
      } catch (error) {
        if (error instanceof TranscryptorError &&
            error.type === 'InvalidSession') {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          encryptedPseudonyms = await transcryptor.pseudonymizeBatch(
              encryptedPseudonyms,
              domainFrom,
              domainTo,
              sessionFrom,
              sessionTo
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return encryptedPseudonyms;
  }

  /**
   * Rekey an encrypted data point through all transcryptors
   */
  public async rekey(
      encryptedDataPoint: EncryptedDataPoint,
      sessionsFrom: EncryptionContexts
  ): Promise<EncryptedDataPoint> {
    if (!this.pepCryptoClient) {
      await this.init();
    }
    // Rekey through each transcryptor
    for (let i = 0; i < this.transcryptors.length; i++) {
      const transcryptor = this.transcryptors[i];
      const systemId = transcryptor.getSystemId();

      const sessionFrom = sessionsFrom.get(systemId);
      if (!sessionFrom) {
        throw PseudonymServiceError.missingSession(systemId);
      }

      const sessionTo = transcryptor.getSessionId();
      if (!sessionTo) {
        throw PseudonymServiceError.uninitializedTranscryptor();
      }

      try {
        encryptedDataPoint = await transcryptor.rekey(
            encryptedDataPoint,
            sessionFrom,
            sessionTo
        );
      } catch (error) {
        if (error instanceof TranscryptorError &&
            error.type === 'InvalidSession') {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          encryptedDataPoint = await transcryptor.rekey(
              encryptedDataPoint,
              sessionFrom,
              sessionTo
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return encryptedDataPoint;
  }

  /**
   * Rekey a batch of encrypted data points through all transcryptors
   */
  public async rekeyBatch(
      encryptedDataPoints: EncryptedDataPoint[],
      sessionsFrom: EncryptionContexts
  ): Promise<EncryptedDataPoint[]> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    // Rekey through each transcryptor
    for (let i = 0; i < this.transcryptors.length; i++) {
      const transcryptor = this.transcryptors[i];
      const systemId = transcryptor.getSystemId();

      const sessionFrom = sessionsFrom.get(systemId);
      if (!sessionFrom) {
        throw PseudonymServiceError.missingSession(systemId);
      }

      const sessionTo = transcryptor.getSessionId();
      if (!sessionTo) {
        throw PseudonymServiceError.uninitializedTranscryptor();
      }

      try {
        encryptedDataPoints = await transcryptor.rekeyBatch(
            encryptedDataPoints,
            sessionFrom,
            sessionTo
        );
      } catch (error) {
        if (error instanceof TranscryptorError &&
            error.type === 'InvalidSession') {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          encryptedDataPoints = await transcryptor.rekeyBatch(
              encryptedDataPoints,
              sessionFrom,
              sessionTo
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return encryptedDataPoints;
  }

  /**
   * Transcrypt entity data through all transcryptors
   */
  public async transcrypt(
      encrypted: EncryptedEntityData[],
      sessionsFrom: EncryptionContexts,
      domainFrom: PseudonymizationDomain,
      domainTo: PseudonymizationDomain
  ): Promise<EncryptedEntityData[]> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    // Transcrypt through each transcryptor
    for (let i = 0; i < this.transcryptors.length; i++) {
      const transcryptor = this.transcryptors[i];
      const systemId = transcryptor.getSystemId();

      const sessionFrom = sessionsFrom.get(systemId);
      if (!sessionFrom) {
        throw PseudonymServiceError.missingSession(systemId);
      }

      const sessionTo = transcryptor.getSessionId();
      if (!sessionTo) {
        throw PseudonymServiceError.uninitializedTranscryptor();
      }

      try {
        encrypted = await transcryptor.transcrypt(
            encrypted,
            domainFrom,
            domainTo,
            sessionFrom,
            sessionTo
        );
      } catch (error) {
        if (error instanceof TranscryptorError &&
            error.type === 'InvalidSession') {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          encrypted = await transcryptor.transcrypt(
              encrypted,
              domainFrom,
              domainTo,
              sessionFrom,
              sessionTo
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return encrypted;
  }

  /**
   * Encrypt a message using the PEPClient
   */
  public async encrypt(message: Pseudonym | DataPoint): Promise<[EncryptedPseudonym | EncryptedDataPoint, EncryptionContexts]> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    if (!this.pepCryptoClient) {
      throw PseudonymServiceError.uninitializedPEPClient();
    }

    let encrypted: EncryptedPseudonym | EncryptedDataPoint;
    if (message instanceof Pseudonym) {
      encrypted = this.pepCryptoClient.encryptPseudonym(message);
    } else {
      encrypted = this.pepCryptoClient.encryptData(message as DataPoint);
    }

    return [encrypted, this.getCurrentSessions()];
  }

  /**
   * Get the current sessions
   */
  public getCurrentSessions(): EncryptionContexts {
    const sessionsMap = new Map<SystemId, EncryptionContext>();

    for (const transcryptor of this.transcryptors) {
      const sessionId = transcryptor.getSessionId();
      if (!sessionId) {
        throw PseudonymServiceError.uninitializedTranscryptor();
      }

      sessionsMap.set(transcryptor.getSystemId(), sessionId);
    }

    return new EncryptionContexts(sessionsMap);
  }

  /**
   * Decrypt an encrypted message using the PEPClient
   */
  public decrypt(encrypted: EncryptedPseudonym | EncryptedDataPoint): Pseudonym | DataPoint {
    if (!this.pepCryptoClient) {
      throw PseudonymServiceError.uninitializedPEPClient();
    }

    if (encrypted instanceof EncryptedPseudonym) {
      return this.pepCryptoClient.decryptPseudonym(encrypted);
    } else {
      return this.pepCryptoClient.decryptData(encrypted as EncryptedDataPoint);
    }
  }

}