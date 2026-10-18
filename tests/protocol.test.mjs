import test from 'node:test';
import assert from 'node:assert/strict';
import {
  X25519_MLKEM_768,
  getHybridGroupParameters,
  serializeClientKeyShare,
  deserializeClientKeyShare,
  serializeServerKeyShare,
  deserializeServerKeyShare,
  constantTimeEqual
} from '../dist/index.js';

test('Hybrid TLS Protocol: X25519MLKEM768 Parameter Invariants', () => {
  assert.equal(X25519_MLKEM_768.name, 'X25519MLKEM768');
  assert.equal(X25519_MLKEM_768.codePoint, 0x11ec); // 4588
  assert.equal(X25519_MLKEM_768.classicalAlgorithm, 'X25519');
  assert.equal(X25519_MLKEM_768.pqcAlgorithm, 'ML-KEM-768');
  assert.equal(X25519_MLKEM_768.classicalPublicKeyBytes, 32);
  assert.equal(X25519_MLKEM_768.classicalSecretKeyBytes, 32);
  assert.equal(X25519_MLKEM_768.pqcEncapsulationKeyBytes, 1184);
  assert.equal(X25519_MLKEM_768.pqcDecapsulationKeyBytes, 2400);
  assert.equal(X25519_MLKEM_768.pqcCiphertextBytes, 1088);
  assert.equal(X25519_MLKEM_768.clientKeyShareBytes, 1216);
  assert.equal(X25519_MLKEM_768.serverKeyShareBytes, 1120);
  assert.equal(X25519_MLKEM_768.combinedSharedSecretBytes, 64);
});

test('Hybrid TLS Protocol: Registry Lookup and Error Handling', () => {
  const p = getHybridGroupParameters('X25519MLKEM768');
  assert.equal(p.codePoint, 0x11ec);

  assert.throws(
    () => getHybridGroupParameters('NON_EXISTENT_GROUP'),
    /UNSUPPORTED_HYBRID_GROUP/
  );
});

test('Hybrid TLS Protocol: ClientKeyShare Serialization Round-Trip', () => {
  const x25519Pk = new Uint8Array(32).fill(0xaa);
  const mlkemEk = new Uint8Array(1184).fill(0xbb);

  const serialized = serializeClientKeyShare({
    x25519PublicKey: x25519Pk,
    mlkemEncapsulationKey: mlkemEk
  });

  assert.equal(serialized.length, 1216);

  const deserialized = deserializeClientKeyShare(serialized);
  assert.ok(constantTimeEqual(deserialized.x25519PublicKey, x25519Pk));
  assert.ok(constantTimeEqual(deserialized.mlkemEncapsulationKey, mlkemEk));
});

test('Hybrid TLS Protocol: ServerKeyShare Serialization Round-Trip', () => {
  const x25519Pk = new Uint8Array(32).fill(0x11);
  const mlkemCt = new Uint8Array(1088).fill(0x22);

  const serialized = serializeServerKeyShare({
    x25519PublicKey: x25519Pk,
    mlkemCiphertext: mlkemCt
  });

  assert.equal(serialized.length, 1120);

  const deserialized = deserializeServerKeyShare(serialized);
  assert.ok(constantTimeEqual(deserialized.x25519PublicKey, x25519Pk));
  assert.ok(constantTimeEqual(deserialized.mlkemCiphertext, mlkemCt));
});

test('Hybrid TLS Protocol: Defensive Length Validation Failures', () => {
  assert.throws(
    () => serializeClientKeyShare({ x25519PublicKey: new Uint8Array(31), mlkemEncapsulationKey: new Uint8Array(1184) }),
    /INVALID_X25519_PK_LENGTH/
  );

  assert.throws(
    () => serializeClientKeyShare({ x25519PublicKey: new Uint8Array(32), mlkemEncapsulationKey: new Uint8Array(1183) }),
    /INVALID_MLKEM_EK_LENGTH/
  );

  assert.throws(
    () => deserializeClientKeyShare(new Uint8Array(1215)),
    /INVALID_CLIENT_KEY_SHARE_LENGTH/
  );

  assert.throws(
    () => deserializeServerKeyShare(new Uint8Array(1119)),
    /INVALID_SERVER_KEY_SHARE_LENGTH/
  );
});

test('Hybrid TLS Protocol: Constant-Time Comparison Invariants', () => {
  const a = new Uint8Array([1, 2, 3]);
  const b = new Uint8Array([1, 2, 3]);
  const c = new Uint8Array([1, 2, 4]);
  const d = new Uint8Array([1, 2]);

  assert.equal(constantTimeEqual(a, b), true);
  assert.equal(constantTimeEqual(a, c), false);
  assert.equal(constantTimeEqual(a, d), false);
});
