import {
  Attribute,
  BlindedAttributeGlobalSecretKey,
  BlindedGlobalKeys,
  BlindedPseudonymGlobalSecretKey,
  Client as PEPClient,
  EncryptedAttribute,
  EncryptedPseudonym,
  EncryptedPEPJSONValue,
  LongAttribute,
  LongEncryptedAttribute,
  LongEncryptedPseudonym,
  LongPseudonym,
  PEPJSONValue,
  Pseudonym,
  SessionKeys,
  SessionKeyShares,
} from "@nolai/libpep-wasm";

import {
  PseudonymizationDomain,
  AnyEncryptedPseudonym,
  AnyEncryptedAttribute,
  AnyEncryptedData,
} from "./messages.js";
import {
  TranscryptorClient,
  TranscryptorError,
} from "./transcryptor_client.js";
import { EncryptionContext, EncryptionContexts, SystemId } from "./sessions.js";
import { PAASConfig } from "./config.js";
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
  InconsistentConfig = "InconsistentConfig",
}

/**
 * Error class for PseudonymService errors
 */
export class PseudonymServiceError extends Error {
  type: PseudonymServiceErrorType;
  details?: Record<string, string>;
  cause?: Error;

  constructor(
    type: PseudonymServiceErrorType,
    message: string,
    cause?: Error,
    details?: Record<string, string>,
  ) {
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
      error,
    );
  }

  static missingAuth(systemId: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
      PseudonymServiceErrorType.MissingAuth,
      `No auth found for system ${systemId}`,
      undefined,
      { systemId },
    );
  }

  static missingSession(systemId: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
      PseudonymServiceErrorType.MissingSession,
      `No session found for system ${systemId}`,
      undefined,
      { systemId },
    );
  }

  static missingSessionKeyShare(systemId: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
      PseudonymServiceErrorType.MissingSessionKeyShare,
      `No session key share found for system ${systemId}`,
      undefined,
      { systemId },
    );
  }

  static uninitializedPEPClient(): PseudonymServiceError {
    return new PseudonymServiceError(
      PseudonymServiceErrorType.UninitializedPEPClient,
      "PEP crypto client not initialized",
    );
  }

  static uninitializedTranscryptor(): PseudonymServiceError {
    return new PseudonymServiceError(
      PseudonymServiceErrorType.UninitializedTranscryptor,
      "Transcryptor does not have session",
    );
  }

  static inconsistentConfig(system: SystemId): PseudonymServiceError {
    return new PseudonymServiceError(
      PseudonymServiceErrorType.InconsistentConfig,
      `Inconsistent config received from ${system}`,
      undefined,
      { system },
    );
  }
}

/**
 * Information needed to store and restore session key shares
 */
export interface SystemSessionKeyShares {
  [systemId: string]: SessionKeyShares; // SessionKeyShare hex string
}

/**
 * Information needed to dump and restore service state
 */
export interface PseudonymServiceDump {
  sessions: EncryptionContexts;
  sessionKeys: SessionKeys;
  sessionKeyShares: SystemSessionKeyShares;
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
    auths: SystemAuths,
  ): Promise<PseudonymService> {
    const service = new PseudonymService(config);

    // Create all transcryptors
    const transcryptorPromises = config.transcryptors.map(async (tc) => {
      const auth = auths.get(tc.system_id);
      if (!auth) {
        throw PseudonymServiceError.missingAuth(tc.system_id);
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
    sessionKeyShares: SystemSessionKeyShares,
    sessionKeys: SessionKeys,
  ): Promise<PseudonymService> {
    const service = new PseudonymService(config);

    // Restore all transcryptors
    const transcryptorPromises = config.transcryptors.map(async (tc) => {
      const auth = auths.get(tc.system_id);
      if (!auth) {
        throw PseudonymServiceError.missingAuth(tc.system_id);
      }

      const sessionId = sessionIds.get(tc.system_id);
      if (!sessionId) {
        throw PseudonymServiceError.missingSession(tc.system_id);
      }

      const keyShare = sessionKeyShares[tc.system_id];
      if (!keyShare) {
        throw PseudonymServiceError.missingSessionKeyShare(tc.system_id);
      }

      try {
        return await TranscryptorClient.restore(tc, auth, sessionId, keyShare);
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
    const sessionKeyShares: SystemSessionKeyShares = {};
    for (const transcryptor of this.transcryptors) {
      const keyShares = transcryptor.getKeyShares();
      if (keyShares) {
        sessionKeyShares[transcryptor.getSystemId()] = keyShares;
      }
    }

    return {
      sessions,
      sessionKeys,
      sessionKeyShares,
    };
  }

  /**
   * Check if the PEP crypto client is initialized
   */
  public isInitialized(): boolean {
    return this.pepCryptoClient !== null;
  }

  /**
   * Initialize the PseudonymService by starting sessions with all transcryptors
   */
  public async init(): Promise<void> {
    const sks: SessionKeyShares[] = [];

    // Start sessions with all transcryptors
    for (const transcryptor of this.transcryptors) {
      try {
        const { keyShares } = await transcryptor.startSession();
        sks.push(keyShares);
      } catch (error) {
        if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        }
        throw error;
      }
    }

    const bgk = new BlindedGlobalKeys(
      BlindedPseudonymGlobalSecretKey.fromHex(
        this.config.blinded_global_keys.pseudonym,
      ),
      BlindedAttributeGlobalSecretKey.fromHex(
        this.config.blinded_global_keys.attribute,
      ),
    );

    // Initialize the PEP crypto client
    this.pepCryptoClient = new PEPClient(bgk, sks);
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
    if (
      transcryptorIndex < 0 ||
      transcryptorIndex >= this.transcryptors.length
    ) {
      throw new Error(`Invalid transcryptor index: ${transcryptorIndex}`);
    }

    const transcryptor = this.transcryptors[transcryptorIndex];
    const oldKeyShares = transcryptor.getKeyShares();

    try {
      // Start a new session for the transcryptor
      const { keyShares: newKeyShares } = await transcryptor.startSession();

      // Update the session key in the PEP crypto client if it exists
      if (oldKeyShares && this.pepCryptoClient) {
        this.pepCryptoClient.updateSessionSecretKeys(
          oldKeyShares,
          newKeyShares,
        );
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
   * Pseudonymize an encrypted pseudonym through all transcryptors.
   * Polymorphic: accepts both EncryptedPseudonym and LongEncryptedPseudonym.
   */
  public async pseudonymize<T extends AnyEncryptedPseudonym>(
    encryptedPseudonym: T,
    sessionsFrom: EncryptionContexts,
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
  ): Promise<T> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    let result = encryptedPseudonym;

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
        result = await transcryptor.pseudonymize(
          result,
          domainFrom,
          domainTo,
          sessionFrom,
          sessionTo,
        );
      } catch (error) {
        if (
          error instanceof TranscryptorError &&
          error.type === "InvalidSession"
        ) {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          result = await transcryptor.pseudonymize(
            result,
            domainFrom,
            domainTo,
            sessionFrom,
            sessionTo,
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return result;
  }

  /**
   * Pseudonymize a batch of encrypted pseudonyms through all transcryptors.
   * Polymorphic: accepts both EncryptedPseudonym[] and LongEncryptedPseudonym[].
   */
  public async pseudonymizeBatch<T extends AnyEncryptedPseudonym>(
    encryptedPseudonyms: T[],
    sessionsFrom: EncryptionContexts,
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
  ): Promise<T[]> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    let result = encryptedPseudonyms;

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
        result = await transcryptor.pseudonymizeBatch(
          result,
          domainFrom,
          domainTo,
          sessionFrom,
          sessionTo,
        );
      } catch (error) {
        if (
          error instanceof TranscryptorError &&
          error.type === "InvalidSession"
        ) {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          result = await transcryptor.pseudonymizeBatch(
            result,
            domainFrom,
            domainTo,
            sessionFrom,
            sessionTo,
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return result;
  }

  /**
   * Rekey an encrypted data point through all transcryptors.
   * Polymorphic: accepts both EncryptedAttribute and LongEncryptedAttribute.
   */
  public async rekey<T extends AnyEncryptedAttribute>(
    encryptedAttribute: T,
    sessionsFrom: EncryptionContexts,
  ): Promise<T> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    let result = encryptedAttribute;

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
        result = await transcryptor.rekey(result, sessionFrom, sessionTo);
      } catch (error) {
        if (
          error instanceof TranscryptorError &&
          error.type === "InvalidSession"
        ) {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          result = await transcryptor.rekey(result, sessionFrom, sessionTo);
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return result;
  }

  /**
   * Rekey a batch of encrypted data points through all transcryptors.
   * Polymorphic: accepts both EncryptedAttribute[] and LongEncryptedAttribute[].
   */
  public async rekeyBatch<T extends AnyEncryptedAttribute>(
    encryptedAttributes: T[],
    sessionsFrom: EncryptionContexts,
  ): Promise<T[]> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    let result = encryptedAttributes;

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
        result = await transcryptor.rekeyBatch(result, sessionFrom, sessionTo);
      } catch (error) {
        if (
          error instanceof TranscryptorError &&
          error.type === "InvalidSession"
        ) {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          result = await transcryptor.rekeyBatch(
            result,
            sessionFrom,
            sessionTo,
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return result;
  }

  /**
   * Transcrypt entity data through all transcryptors.
   * Polymorphic: accepts EncryptedData, LongEncryptedData, or EncryptedPEPJSONValue.
   */
  public async transcrypt<T extends AnyEncryptedData>(
    encrypted: T,
    sessionsFrom: EncryptionContexts,
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
  ): Promise<T> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    let result = encrypted;

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
        result = await transcryptor.transcrypt(
          result,
          domainFrom,
          domainTo,
          sessionFrom,
          sessionTo,
        );
      } catch (error) {
        if (
          error instanceof TranscryptorError &&
          error.type === "InvalidSession"
        ) {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          result = await transcryptor.transcrypt(
            result,
            domainFrom,
            domainTo,
            sessionFrom,
            sessionTo,
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return result;
  }

  /**
   * Transcrypt a batch of entity data through all transcryptors.
   * Polymorphic: accepts EncryptedData[], LongEncryptedData[], or EncryptedPEPJSONValue[].
   */
  public async transcryptBatch<T extends AnyEncryptedData>(
    encrypted: T[],
    sessionsFrom: EncryptionContexts,
    domainFrom: PseudonymizationDomain,
    domainTo: PseudonymizationDomain,
  ): Promise<T[]> {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    let result = encrypted;

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
        result = await transcryptor.transcryptBatch(
          result,
          domainFrom,
          domainTo,
          sessionFrom,
          sessionTo,
        );
      } catch (error) {
        if (
          error instanceof TranscryptorError &&
          error.type === "InvalidSession"
        ) {
          // If session is invalid, refresh it and try again
          await this.refreshSession(i);

          result = await transcryptor.transcryptBatch(
            result,
            domainFrom,
            domainTo,
            sessionFrom,
            sessionTo,
          );
        } else if (error instanceof TranscryptorError) {
          throw PseudonymServiceError.transcryptorError(error);
        } else {
          throw error;
        }
      }
    }

    return result;
  }

  /**
   * Encryptable message types
   */
  public async encrypt(
    message: Pseudonym,
  ): Promise<[EncryptedPseudonym, EncryptionContexts]>;
  public async encrypt(
    message: Attribute,
  ): Promise<[EncryptedAttribute, EncryptionContexts]>;
  public async encrypt(
    message: LongPseudonym,
  ): Promise<[LongEncryptedPseudonym, EncryptionContexts]>;
  public async encrypt(
    message: LongAttribute,
  ): Promise<[LongEncryptedAttribute, EncryptionContexts]>;
  public async encrypt(
    message: PEPJSONValue,
  ): Promise<[EncryptedPEPJSONValue, EncryptionContexts]>;
  /**
   * Encrypt a message using the PEPClient.
   * Polymorphic: accepts Pseudonym, Attribute, LongPseudonym, LongAttribute, or PEPJSONValue.
   */
  public async encrypt(
    message:
      | Pseudonym
      | Attribute
      | LongPseudonym
      | LongAttribute
      | PEPJSONValue,
  ): Promise<
    [
      (
        | EncryptedPseudonym
        | EncryptedAttribute
        | LongEncryptedPseudonym
        | LongEncryptedAttribute
        | EncryptedPEPJSONValue
      ),
      EncryptionContexts,
    ]
  > {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    if (!this.pepCryptoClient) {
      throw PseudonymServiceError.uninitializedPEPClient();
    }

    let encrypted:
      | EncryptedPseudonym
      | EncryptedAttribute
      | LongEncryptedPseudonym
      | LongEncryptedAttribute
      | EncryptedPEPJSONValue;

    if (message instanceof Pseudonym) {
      encrypted = this.pepCryptoClient.encryptPseudonym(message);
    } else if (message instanceof Attribute) {
      encrypted = this.pepCryptoClient.encryptData(message);
    } else if (message instanceof LongPseudonym) {
      encrypted = this.pepCryptoClient.encryptLongPseudonym(message);
    } else if (message instanceof LongAttribute) {
      encrypted = this.pepCryptoClient.encryptLongData(message);
    } else {
      // PEPJSONValue
      encrypted = this.pepCryptoClient.encryptJSON(message as PEPJSONValue);
    }

    return [encrypted, this.getCurrentSessions()];
  }

  /**
   * Batch encrypt messages using the PEPClient.
   * All messages must be of the same type.
   */
  public async encryptBatch(
    messages: Pseudonym[],
  ): Promise<[EncryptedPseudonym[], EncryptionContexts]>;
  public async encryptBatch(
    messages: Attribute[],
  ): Promise<[EncryptedAttribute[], EncryptionContexts]>;
  public async encryptBatch(
    messages: LongPseudonym[],
  ): Promise<[LongEncryptedPseudonym[], EncryptionContexts]>;
  public async encryptBatch(
    messages: LongAttribute[],
  ): Promise<[LongEncryptedAttribute[], EncryptionContexts]>;
  public async encryptBatch(
    messages: Pseudonym[] | Attribute[] | LongPseudonym[] | LongAttribute[],
  ): Promise<
    [
      (
        | EncryptedPseudonym[]
        | EncryptedAttribute[]
        | LongEncryptedPseudonym[]
        | LongEncryptedAttribute[]
      ),
      EncryptionContexts,
    ]
  > {
    if (!this.pepCryptoClient) {
      await this.init();
    }

    if (!this.pepCryptoClient) {
      throw PseudonymServiceError.uninitializedPEPClient();
    }

    if (messages.length === 0) {
      return [[], this.getCurrentSessions()];
    }

    const first = messages[0];
    let encrypted:
      | EncryptedPseudonym[]
      | EncryptedAttribute[]
      | LongEncryptedPseudonym[]
      | LongEncryptedAttribute[];

    if (first instanceof Pseudonym) {
      encrypted = this.pepCryptoClient.encryptPseudonymBatch(
        messages as Pseudonym[],
      );
    } else if (first instanceof Attribute) {
      encrypted = this.pepCryptoClient.encryptDataBatch(
        messages as Attribute[],
      );
    } else if (first instanceof LongPseudonym) {
      encrypted = this.pepCryptoClient.encryptLongPseudonymBatch(
        messages as LongPseudonym[],
      );
    } else {
      encrypted = this.pepCryptoClient.encryptLongDataBatch(
        messages as LongAttribute[],
      );
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
   * Decryptable encrypted types
   */
  public decrypt(encrypted: EncryptedPseudonym): Pseudonym;
  public decrypt(encrypted: EncryptedAttribute): Attribute;
  public decrypt(encrypted: LongEncryptedPseudonym): LongPseudonym;
  public decrypt(encrypted: LongEncryptedAttribute): LongAttribute;
  public decrypt(encrypted: EncryptedPEPJSONValue): PEPJSONValue;
  /**
   * Decrypt an encrypted message using the PEPClient.
   * Polymorphic: accepts EncryptedPseudonym, EncryptedAttribute, LongEncryptedPseudonym, LongEncryptedAttribute, or EncryptedPEPJSONValue.
   */
  public decrypt(
    encrypted:
      | EncryptedPseudonym
      | EncryptedAttribute
      | LongEncryptedPseudonym
      | LongEncryptedAttribute
      | EncryptedPEPJSONValue,
  ): Pseudonym | Attribute | LongPseudonym | LongAttribute | PEPJSONValue {
    if (!this.pepCryptoClient) {
      throw PseudonymServiceError.uninitializedPEPClient();
    }

    if (encrypted instanceof EncryptedPseudonym) {
      return this.pepCryptoClient.decryptPseudonym(encrypted);
    } else if (encrypted instanceof EncryptedAttribute) {
      return this.pepCryptoClient.decryptData(encrypted);
    } else if (encrypted instanceof LongEncryptedPseudonym) {
      return this.pepCryptoClient.decryptLongPseudonym(encrypted);
    } else if (encrypted instanceof LongEncryptedAttribute) {
      return this.pepCryptoClient.decryptLongData(encrypted);
    } else {
      // EncryptedPEPJSONValue
      return this.pepCryptoClient.decryptJSON(
        encrypted as EncryptedPEPJSONValue,
      );
    }
  }

  /**
   * Batch decrypt encrypted messages using the PEPClient.
   * All messages must be of the same type.
   */
  public decryptBatch(encrypted: EncryptedPseudonym[]): Pseudonym[];
  public decryptBatch(encrypted: EncryptedAttribute[]): Attribute[];
  public decryptBatch(encrypted: LongEncryptedPseudonym[]): LongPseudonym[];
  public decryptBatch(encrypted: LongEncryptedAttribute[]): LongAttribute[];
  public decryptBatch(
    encrypted:
      | EncryptedPseudonym[]
      | EncryptedAttribute[]
      | LongEncryptedPseudonym[]
      | LongEncryptedAttribute[],
  ): Pseudonym[] | Attribute[] | LongPseudonym[] | LongAttribute[] {
    if (!this.pepCryptoClient) {
      throw PseudonymServiceError.uninitializedPEPClient();
    }

    if (encrypted.length === 0) {
      return [];
    }

    const first = encrypted[0];

    if (first instanceof EncryptedPseudonym) {
      return this.pepCryptoClient.decryptPseudonymBatch(
        encrypted as EncryptedPseudonym[],
      );
    } else if (first instanceof EncryptedAttribute) {
      return this.pepCryptoClient.decryptDataBatch(
        encrypted as EncryptedAttribute[],
      );
    } else if (first instanceof LongEncryptedPseudonym) {
      return this.pepCryptoClient.decryptLongPseudonymBatch(
        encrypted as LongEncryptedPseudonym[],
      );
    } else {
      return this.pepCryptoClient.decryptLongDataBatch(
        encrypted as LongEncryptedAttribute[],
      );
    }
  }
}
