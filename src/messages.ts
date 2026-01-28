import {
  EncryptedPseudonym,
  EncryptedAttribute,
  LongEncryptedPseudonym,
  LongEncryptedAttribute,
  EncryptedPEPJSONValue,
} from "@nolai/libpep-wasm";

// =============================================================================
// Data Types (matching libpep Rust types)
// =============================================================================

/**
 * Encrypted data pair containing pseudonyms and attributes.
 * This is how EncryptedData serializes in JSON.
 */
export type EncryptedDataJson = [string[], string[]];

/**
 * Pseudonymization domain type
 */
export type PseudonymizationDomain = string;

// =============================================================================
// Status and Session Types
// =============================================================================

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
  session_key_shares: {
    pseudonym: string;
    attribute: string;
  };
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

// =============================================================================
// Pseudonymization Request/Response Types
// =============================================================================

/**
 * Request to pseudonymize a single encrypted pseudonym (Normal variant)
 */
export interface PseudonymizationRequest {
  encrypted_pseudonym: string; // base64-encoded EncryptedPseudonym
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from pseudonymizing an encrypted pseudonym (Normal variant)
 */
export interface PseudonymizationResponse {
  encrypted_pseudonym: string; // base64-encoded EncryptedPseudonym
}

/**
 * Request to pseudonymize a single long encrypted pseudonym
 */
export interface LongPseudonymizationRequest {
  encrypted_pseudonym: string; // pipe-delimited base64 LongEncryptedPseudonym
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from pseudonymizing a long encrypted pseudonym
 */
export interface LongPseudonymizationResponse {
  encrypted_pseudonym: string; // pipe-delimited base64 LongEncryptedPseudonym
}

/**
 * Request to pseudonymize a batch of encrypted pseudonyms (Normal variant)
 */
export interface PseudonymizationBatchRequest {
  encrypted_pseudonyms: string[]; // base64-encoded EncryptedPseudonyms
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from pseudonymizing a batch of encrypted pseudonyms (Normal variant)
 */
export interface PseudonymizationBatchResponse {
  encrypted_pseudonyms: string[]; // base64-encoded EncryptedPseudonyms
}

/**
 * Request to pseudonymize a batch of long encrypted pseudonyms
 */
export interface LongPseudonymizationBatchRequest {
  encrypted_pseudonyms: string[]; // pipe-delimited base64 LongEncryptedPseudonyms
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from pseudonymizing a batch of long encrypted pseudonyms
 */
export interface LongPseudonymizationBatchResponse {
  encrypted_pseudonyms: string[]; // pipe-delimited base64 LongEncryptedPseudonyms
}

// =============================================================================
// Rekey Request/Response Types
// =============================================================================

/**
 * Request to rekey an encrypted attribute (Normal variant)
 */
export interface RekeyRequest {
  encrypted_attribute: string; // base64-encoded EncryptedAttribute
  session_from: string;
  session_to: string;
}

/**
 * Response from rekeying an encrypted attribute (Normal variant)
 */
export interface RekeyResponse {
  encrypted_attribute: string; // base64-encoded EncryptedAttribute
}

/**
 * Request to rekey a long encrypted attribute
 */
export interface LongRekeyRequest {
  encrypted_attribute: string; // pipe-delimited base64 LongEncryptedAttribute
  session_from: string;
  session_to: string;
}

/**
 * Response from rekeying a long encrypted attribute
 */
export interface LongRekeyResponse {
  encrypted_attribute: string; // pipe-delimited base64 LongEncryptedAttribute
}

/**
 * Request to rekey a batch of encrypted attributes (Normal variant)
 */
export interface RekeyBatchRequest {
  encrypted_attributes: string[]; // base64-encoded EncryptedAttributes
  session_from: string;
  session_to: string;
}

/**
 * Response from rekeying a batch of encrypted attributes (Normal variant)
 */
export interface RekeyBatchResponse {
  encrypted_attributes: string[]; // base64-encoded EncryptedAttributes
}

/**
 * Request to rekey a batch of long encrypted attributes
 */
export interface LongRekeyBatchRequest {
  encrypted_attributes: string[]; // pipe-delimited base64 LongEncryptedAttributes
  session_from: string;
  session_to: string;
}

/**
 * Response from rekeying a batch of long encrypted attributes
 */
export interface LongRekeyBatchResponse {
  encrypted_attributes: string[]; // pipe-delimited base64 LongEncryptedAttributes
}

// =============================================================================
// Transcryption Request/Response Types
// =============================================================================

/**
 * Request to transcrypt encrypted data (Normal variant)
 */
export interface TranscryptionRequest {
  encrypted: EncryptedDataJson; // [pseudonyms[], attributes[]]
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from transcrypting encrypted data (Normal variant)
 */
export interface TranscryptionResponse {
  encrypted: EncryptedDataJson; // [pseudonyms[], attributes[]]
}

/**
 * Request to transcrypt long encrypted data
 */
export interface LongTranscryptionRequest {
  encrypted: EncryptedDataJson; // [long_pseudonyms[], long_attributes[]]
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from transcrypting long encrypted data
 */
export interface LongTranscryptionResponse {
  encrypted: EncryptedDataJson; // [long_pseudonyms[], long_attributes[]]
}

/**
 * Request to transcrypt a batch of encrypted data (Normal variant)
 */
export interface TranscryptionBatchRequest {
  encrypted: EncryptedDataJson[]; // Array of [pseudonyms[], attributes[]]
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from transcrypting a batch of encrypted data (Normal variant)
 */
export interface TranscryptionBatchResponse {
  encrypted: EncryptedDataJson[]; // Array of [pseudonyms[], attributes[]]
}

/**
 * Request to transcrypt a batch of long encrypted data
 */
export interface LongTranscryptionBatchRequest {
  encrypted: EncryptedDataJson[]; // Array of [long_pseudonyms[], long_attributes[]]
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from transcrypting a batch of long encrypted data
 */
export interface LongTranscryptionBatchResponse {
  encrypted: EncryptedDataJson[]; // Array of [long_pseudonyms[], long_attributes[]]
}

/**
 * Request to transcrypt JSON encrypted data
 */
export interface JsonTranscryptionRequest {
  encrypted: string; // JSON-serialized EncryptedPEPJSONValue
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from transcrypting JSON encrypted data
 */
export interface JsonTranscryptionResponse {
  encrypted: string; // JSON-serialized EncryptedPEPJSONValue
}

/**
 * Request to transcrypt a batch of JSON encrypted data
 */
export interface JsonTranscryptionBatchRequest {
  encrypted: string[]; // JSON-serialized EncryptedPEPJSONValues
  domain_from: string;
  domain_to: string;
  session_from: string;
  session_to: string;
}

/**
 * Response from transcrypting a batch of JSON encrypted data
 */
export interface JsonTranscryptionBatchResponse {
  encrypted: string[]; // JSON-serialized EncryptedPEPJSONValues
}

// =============================================================================
// Runtime Data Types (for internal use with wasm objects)
// =============================================================================

/**
 * Encrypted data with wasm object types (for internal use)
 */
export interface EncryptedData {
  encrypted_pseudonym: EncryptedPseudonym[];
  encrypted_attribute: EncryptedAttribute[];
}

/**
 * Long encrypted data with wasm object types (for internal use)
 */
export interface LongEncryptedData {
  encrypted_pseudonym: LongEncryptedPseudonym[];
  encrypted_attribute: LongEncryptedAttribute[];
}

// =============================================================================
// Helper types for polymorphic API
// =============================================================================

/**
 * Union type for all pseudonym types that can be used with pseudonymize
 */
export type AnyEncryptedPseudonym = EncryptedPseudonym | LongEncryptedPseudonym;

/**
 * Union type for all attribute types that can be used with rekey
 */
export type AnyEncryptedAttribute = EncryptedAttribute | LongEncryptedAttribute;

/**
 * Union type for all data types that can be used with transcrypt
 */
export type AnyEncryptedData =
  | EncryptedData
  | LongEncryptedData
  | EncryptedPEPJSONValue;

// =============================================================================
// Type guards for detecting data types
// =============================================================================

/**
 * Check if a pseudonym is a LongEncryptedPseudonym
 */
export function isLongEncryptedPseudonym(
  pseudonym: AnyEncryptedPseudonym,
): pseudonym is LongEncryptedPseudonym {
  return "encryptedPseudonyms" in pseudonym;
}

/**
 * Check if an attribute is a LongEncryptedAttribute
 */
export function isLongEncryptedAttribute(
  attribute: AnyEncryptedAttribute,
): attribute is LongEncryptedAttribute {
  return "encryptedAttributes" in attribute;
}

/**
 * Check if data is EncryptedPEPJSONValue
 */
export function isEncryptedPEPJSONValue(
  data: AnyEncryptedData,
): data is EncryptedPEPJSONValue {
  return "structure" in data && typeof data.structure === "function";
}

/**
 * Check if data is LongEncryptedData
 */
export function isLongEncryptedData(
  data: AnyEncryptedData,
): data is LongEncryptedData {
  if (isEncryptedPEPJSONValue(data)) return false;
  const d = data as EncryptedData | LongEncryptedData;
  return (
    d.encrypted_pseudonym.length > 0 &&
    isLongEncryptedPseudonym(d.encrypted_pseudonym[0] as AnyEncryptedPseudonym)
  );
}
