/**
 * QMOOSA Post-Quantum Cryptography Specification
 * Hybrid Classical / Post-Quantum Key Exchange for TLS 1.3
 *
 * Implements standard parameter definitions, group codepoints, byte layouts,
 * and wire serialization per IETF draft-ietf-tls-hybrid-design and NIST FIPS 203.
 * Primary standard: X25519MLKEM768 (Group codepoint 0x11ec).
 */

import { timingSafeEqual } from 'node:crypto';

export type HybridNamedGroup = 'X25519MLKEM768' | 'SecP256r1MLKEM768';

export interface HybridGroupParameters {
  readonly name: HybridNamedGroup;
  readonly codePoint: number;
  readonly classicalAlgorithm: 'X25519' | 'P-256';
  readonly pqcAlgorithm: 'ML-KEM-768';
  readonly classicalPublicKeyBytes: number;
  readonly classicalSecretKeyBytes: number;
  readonly pqcEncapsulationKeyBytes: number;
  readonly pqcDecapsulationKeyBytes: number;
  readonly pqcCiphertextBytes: number;
  readonly clientKeyShareBytes: number;
  readonly serverKeyShareBytes: number;
  readonly combinedSharedSecretBytes: number;
  readonly description: string;
}

/**
 * X25519MLKEM768: IETF draft-ietf-tls-hybrid-design codepoint 0x11ec (4588)
 * Combines classical ECDH over Curve25519 with NIST FIPS 203 ML-KEM-768.
 * ClientKeyShare: 32 B (X25519 pk) + 1,184 B (ML-KEM-768 ek) = 1,216 bytes.
 * ServerKeyShare: 32 B (X25519 pk) + 1,088 B (ML-KEM-768 ct) = 1,120 bytes.
 * Combined Shared Secret: 32 B (ss_pqc) + 32 B (ss_ecdh) = 64 bytes.
 */
export const X25519_MLKEM_768: Readonly<HybridGroupParameters> = Object.freeze({
  name: 'X25519MLKEM768',
  codePoint: 0x11ec,
  classicalAlgorithm: 'X25519',
  pqcAlgorithm: 'ML-KEM-768',
  classicalPublicKeyBytes: 32,
  classicalSecretKeyBytes: 32,
  pqcEncapsulationKeyBytes: 1184,
  pqcDecapsulationKeyBytes: 2400,
  pqcCiphertextBytes: 1088,
  clientKeyShareBytes: 1216,
  serverKeyShareBytes: 1120,
  combinedSharedSecretBytes: 64,
  description: 'Hybrid X25519 + ML-KEM-768 key exchange for quantum-safe TLS 1.3 transport'
});

export const HYBRID_GROUP_REGISTRY: ReadonlyMap<HybridNamedGroup, Readonly<HybridGroupParameters>> = new Map([
  [X25519_MLKEM_768.name, X25519_MLKEM_768]
]);

export function getHybridGroupParameters(group: HybridNamedGroup): Readonly<HybridGroupParameters> {
  const params = HYBRID_GROUP_REGISTRY.get(group);
  if (!params) {
    throw new Error(`UNSUPPORTED_HYBRID_GROUP: Group "${group}" is not registered`);
  }
  return params;
}

export interface HybridClientKeyShare {
  readonly x25519PublicKey: Uint8Array;
  readonly mlkemEncapsulationKey: Uint8Array;
}

export interface HybridServerKeyShare {
  readonly x25519PublicKey: Uint8Array;
  readonly mlkemCiphertext: Uint8Array;
}

export interface HybridTlsSessionKeys {
  readonly clientWriteKey: Uint8Array;
  readonly serverWriteKey: Uint8Array;
  readonly clientWriteIV: Uint8Array;
  readonly serverWriteIV: Uint8Array;
  readonly clientTrafficSecret: Uint8Array;
  readonly serverTrafficSecret: Uint8Array;
}

export interface TlsRecordHeader {
  readonly contentType: number; // 20: ChangeCipherSpec, 21: Alert, 22: Handshake, 23: ApplicationData
  readonly legacyVersion: number; // 0x0303 for TLS 1.2/1.3 compatibility
  readonly length: number;
}

export interface EncryptedTlsRecord {
  readonly header: TlsRecordHeader;
  readonly ciphertext: Uint8Array;
  readonly authTag: Uint8Array;
  readonly sequenceNumber: bigint;
}

/**
 * Serializes a Hybrid ClientKeyShare to wire bytes (X25519_pk || MLKEM_ek).
 */
export function serializeClientKeyShare(share: HybridClientKeyShare, params: HybridGroupParameters = X25519_MLKEM_768): Uint8Array {
  if (share.x25519PublicKey.length !== params.classicalPublicKeyBytes) {
    throw new Error(`INVALID_X25519_PK_LENGTH: Expected ${params.classicalPublicKeyBytes} bytes, got ${share.x25519PublicKey.length}`);
  }
  if (share.mlkemEncapsulationKey.length !== params.pqcEncapsulationKeyBytes) {
    throw new Error(`INVALID_MLKEM_EK_LENGTH: Expected ${params.pqcEncapsulationKeyBytes} bytes, got ${share.mlkemEncapsulationKey.length}`);
  }

  const out = new Uint8Array(params.clientKeyShareBytes);
  out.set(share.x25519PublicKey, 0);
  out.set(share.mlkemEncapsulationKey, params.classicalPublicKeyBytes);
  return out;
}

/**
 * Deserializes wire bytes into a Hybrid ClientKeyShare.
 */
export function deserializeClientKeyShare(bytes: Uint8Array, params: HybridGroupParameters = X25519_MLKEM_768): HybridClientKeyShare {
  if (!(bytes instanceof Uint8Array) || bytes.length !== params.clientKeyShareBytes) {
    throw new Error(`INVALID_CLIENT_KEY_SHARE_LENGTH: Expected ${params.clientKeyShareBytes} bytes, got ${bytes?.length}`);
  }

  const x25519PublicKey = new Uint8Array(bytes.subarray(0, params.classicalPublicKeyBytes));
  const mlkemEncapsulationKey = new Uint8Array(bytes.subarray(params.classicalPublicKeyBytes, params.clientKeyShareBytes));

  return { x25519PublicKey, mlkemEncapsulationKey };
}

/**
 * Serializes a Hybrid ServerKeyShare to wire bytes (X25519_pk || MLKEM_ct).
 */
export function serializeServerKeyShare(share: HybridServerKeyShare, params: HybridGroupParameters = X25519_MLKEM_768): Uint8Array {
  if (share.x25519PublicKey.length !== params.classicalPublicKeyBytes) {
    throw new Error(`INVALID_X25519_PK_LENGTH: Expected ${params.classicalPublicKeyBytes} bytes, got ${share.x25519PublicKey.length}`);
  }
  if (share.mlkemCiphertext.length !== params.pqcCiphertextBytes) {
    throw new Error(`INVALID_MLKEM_CT_LENGTH: Expected ${params.pqcCiphertextBytes} bytes, got ${share.mlkemCiphertext.length}`);
  }

  const out = new Uint8Array(params.serverKeyShareBytes);
  out.set(share.x25519PublicKey, 0);
  out.set(share.mlkemCiphertext, params.classicalPublicKeyBytes);
  return out;
}

/**
 * Deserializes wire bytes into a Hybrid ServerKeyShare.
 */
export function deserializeServerKeyShare(bytes: Uint8Array, params: HybridGroupParameters = X25519_MLKEM_768): HybridServerKeyShare {
  if (!(bytes instanceof Uint8Array) || bytes.length !== params.serverKeyShareBytes) {
    throw new Error(`INVALID_SERVER_KEY_SHARE_LENGTH: Expected ${params.serverKeyShareBytes} bytes, got ${bytes?.length}`);
  }

  const x25519PublicKey = new Uint8Array(bytes.subarray(0, params.classicalPublicKeyBytes));
  const mlkemCiphertext = new Uint8Array(bytes.subarray(params.classicalPublicKeyBytes, params.serverKeyShareBytes));

  return { x25519PublicKey, mlkemCiphertext };
}

/**
 * Constant-time byte array comparison.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
