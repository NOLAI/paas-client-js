import {EncryptedDataPoint, EncryptedPseudonym} from "@nolai/libpep-wasm";

export interface EncryptedEntityData {
  encrypted_pseudonym: EncryptedPseudonym;
  encrypted_data_points: EncryptedDataPoint[];
}

export interface EncryptedEntityDataJson {
  encrypted_pseudonym: string;
  encrypted_data_points: string[];
}

/**
 * Pseudonymization domain type
 */
export type PseudonymizationDomain = string;

/**
 * Version information for the server
 */
export interface VersionInfo {
  protocol_version: string;
  min_supported_version: string;
}

/**
 * Server status response
 */
export interface StatusResponse {
  timestamp: string;
  system_id: string;
  version_info: VersionInfo;
}

/**
 * Response from starting a session
 */
export interface StartSessionResponse {
  session_id: string;
  key_share: string;
}

/**
 * Response from getting sessions
 */
export interface SessionResponse {
  sessions: string[];
}

/**
 * Request to end a session
 */
export interface EndSessionRequest {
  session_id: string;
}

/**
 * Request to pseudonymize an encrypted pseudonym
 */
export interface PseudonymizationRequest {
  encrypted_pseudonym: string;
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from pseudonymizing an encrypted pseudonym
 */
export interface PseudonymizationResponse {
  encrypted_pseudonym: string;
}

/**
 * Request to pseudonymize a batch of encrypted pseudonyms
 */
export interface PseudonymizationBatchRequest {
  encrypted_pseudonyms: string[];
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from pseudonymizing a batch of encrypted pseudonyms
 */
export interface PseudonymizationBatchResponse {
  encrypted_pseudonyms: string[];
}

/**
 * Request to rekey an encrypted data point
 */
export interface RekeyRequest {
  encrypted_data: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from rekeying an encrypted data point
 */
export interface RekeyResponse {
  encrypted_data: string;
}

/**
 * Request to rekey a batch of encrypted data points
 */
export interface RekeyBatchRequest {
  encrypted_data: string[];
  session_from: string;
  session_to: string;
}

/**
 * Response from rekeying a batch of encrypted data points
 */
export interface RekeyBatchResponse {
  encrypted_data: string[];
}

/**
 * Request to transcrypt entity data
 */
export interface TranscryptionRequest {
  encrypted: EncryptedEntityDataJson[];
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from transcrypting entity data
 */
export interface TranscryptionResponse {
  encrypted: EncryptedEntityDataJson[];
}