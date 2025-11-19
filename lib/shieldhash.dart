library shieldhash;

/// shieldhash - bcrypt-style API with PBKDF2-HMAC-SHA256 backend
/// NOT the original Blowfish bcrypt algorithm — API-compatible design.
///
/// Format:
/// $shield$<version>$<rounds>$<salt_b64>$<derivedKey_b64>
///
/// Example:
/// $shield$1$12$<salt>$<dk>
///
/// rounds: cost/work factor integer. Iterations = 2^rounds (capped reasonably).

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

const _version = 1;
const _prefix = r'$shield$';

/// Maximum allowed rounds to avoid extreme CPU time.
const int maxRounds = 30; // 2^30 iterations would be huge; you can pick lower in production.

/// Minimum allowed rounds.
const int minRounds = 8; // 2^8 = 256 iterations (not very strong) — default recommend >= 12

/// Default rounds if none provided (12 => 4096 iterations).
const int defaultRounds = 12;

/// Salt length in bytes.
const int saltLength = 16;

/// Derived key length in bytes (recommend 32 for SHA256).
const int dkLength = 32;

/// Map rounds -> iterations. By default: iterations = 2^rounds.
/// This is exponential; callers should pick rounds such that iterations are acceptable on their target machines.
int _roundsToIterations(int rounds) {
  // Cap to avoid overflow and extreme iteration counts
  final r = rounds.clamp(minRounds, maxRounds);
  return 1 << r; // 2^r
}

/// Generate cryptographically secure random bytes.
Uint8List _secureRandomBytes(int length) {
  final rnd = Random.secure();
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = rnd.nextInt(256);
  }
  return out;
}

/// Base64 URL-safe encode without padding for compactness.
String _b64Encode(Uint8List bytes) => base64Url.encode(bytes).replaceAll('=', '');

/// Base64 URL-safe decode (accepts no-padding strings).
Uint8List _b64Decode(String s) {
  // Add padding if necessary
  var modulo = s.length % 4;
  var padded = s;
  if (modulo != 0) {
    padded += '=' * (4 - modulo);
  }
  return Uint8List.fromList(base64Url.decode(padded));
}

/// PBKDF2-HMAC-SHA256 derivation.
/// Uses `crypto` package Hmac and sha256.
Uint8List _pbkdf2(Uint8List password, Uint8List salt, int iterations, int dkLen) {
  final hLen = 32; // sha256 output length
  final l = (dkLen + hLen - 1) ~/ hLen;
  final r = dkLen - (l - 1) * hLen;

  final result = Uint8List(l * hLen);
  for (var i = 1; i <= l; i++) {
    // U1 = PRF(password, salt || INT(i))
    final intBlock = _int32BigEndian(i);
    final mac = Hmac(sha256, password);
    var u = mac.convert(Uint8List.fromList([...salt, ...intBlock])).bytes;
    final t = Uint8List.fromList(u);
    for (var j = 1; j < iterations; j++) {
      u = mac.convert(u).bytes;
      for (var k = 0; k < t.length; k++) {
        t[k] ^= u[k];
      }
    }
    // copy t into result
    result.setRange((i - 1) * hLen, (i - 1) * hLen + hLen, t);
  }
  return Uint8List.sublistView(result, 0, dkLen);
}

Uint8List _int32BigEndian(int i) {
  final b = Uint8List(4);
  b[0] = (i >> 24) & 0xff;
  b[1] = (i >> 16) & 0xff;
  b[2] = (i >> 8) & 0xff;
  b[3] = i & 0xff;
  return b;
}

/// Generate a salt string encoding the rounds and salt bytes.
/// This returns just the base64 salt, not the full formatted hash.
///
/// call: genSalt(rounds: 12)
String genSalt({int rounds = defaultRounds}) {
  if (rounds < minRounds || rounds > maxRounds) {
    throw ArgumentError('rounds must be between $minRounds and $maxRounds');
  }
  final salt = _secureRandomBytes(saltLength);
  return _b64Encode(salt);
}

/// Hash a plaintext password and return formatted string:
/// $shield$<version>$<rounds>$<salt_b64>$<derivedKey_b64>
///
/// Example:
/// final hashed = await hash('password', rounds: 12);
String hash(String password, {int rounds = defaultRounds}) {
  if (rounds < minRounds || rounds > maxRounds) {
    throw ArgumentError('rounds must be between $minRounds and $maxRounds');
  }
  final salt = _secureRandomBytes(saltLength);
  final iterations = _roundsToIterations(rounds);

  final dk = _pbkdf2(Uint8List.fromList(utf8.encode(password)), salt, iterations, dkLength);

  final saltB64 = _b64Encode(salt);
  final dkB64 = _b64Encode(dk);

  return '$_prefix$_version\$$rounds\$$saltB64\$$dkB64';
}

/// Verify a password against a stored hash string produced by [hash].
/// Returns true if password matches, false otherwise.
/// Comparison is time-constant.
bool compare(String password, String stored) {
  try {
    if (!stored.startsWith(_prefix)) return false;
    // stored format: $shield$1$12$salt$dk
    final parts = stored.split('\$');
    // ['', 'shield', '1', '12', '<salt>', '<dk>']
    if (parts.length != 6) return false;
    final verStr = parts[2];
    final roundsStr = parts[3];
    final saltB64 = parts[4];
    final dkB64 = parts[5];

    final ver = int.parse(verStr);
    if (ver != _version) return false;

    final rounds = int.parse(roundsStr);
    if (rounds < minRounds || rounds > maxRounds) return false;

    final salt = _b64Decode(saltB64);
    final expectedDk = _b64Decode(dkB64);

    final iterations = _roundsToIterations(rounds);

    final dk = _pbkdf2(Uint8List.fromList(utf8.encode(password)), salt, iterations, expectedDk.length);

    return _constantTimeEquals(dk, expectedDk);
  } catch (e) {
    // parsing error or malformed string
    return false;
  }
}

/// Constant-time byte array comparison.
/// Returns true if identical, false otherwise.
bool _constantTimeEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
