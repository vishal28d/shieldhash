# shieldhash

`shieldhash` — bcrypt-style password hashing API for Dart/Flutter using PBKDF2-HMAC-SHA256.

Features:
- `genSalt({rounds})`
- `hash(password, {rounds})`
- `compare(password, storedHash)`

**Important:** This is **not** the original Blowfish-based bcrypt algorithm. It is designed to be API-compatible and secure for password hashing using PBKDF2-HMAC-SHA256 with an exponential work factor (iterations = 2^rounds).

Usage example:

```dart
import 'package:shieldhash/shieldhash.dart';

final hashed = hash('myPassword', rounds: 12);
final ok = compare('myPassword', hashed);

```
---

# Security notes (please read)
- The implementation uses PBKDF2 with HMAC-SHA256 and an exponential iteration count derived from `rounds` to mimic bcrypt's cost parameter.
- Choose `rounds` appropriate to your target environment. `rounds = 12` → 4096 iterations: moderate. For better security increase rounds (13, 14...) until hashing time fits your threat model.
- For high-security password hashing prefer Argon2 or the original bcrypt algorithm. If you want Argon2 I can provide an Argon2 wrapper (requires bindings) or a pure-Dart implementation (longer job).
- Keep the `dkLength` (derived key length) at 32 bytes for SHA-256.

---

# Next steps I can do for you (pick any)
- Implement the **exact** Blowfish bcrypt algorithm (fully compatible with npm `bcrypt`) as a pure-Dart library.
- Add **Argon2** support (pure Dart or via native bindings).
- Remove the `crypto` dependency by porting PBKDF2/HMAC-SHA256 to pure Dart (no deps).
- Make the package **pub.dev** ready (README badges, CI, versioning).
- Add more utility functions (password strength check, rehash detection when rounds change).

Tell me which next step you want — or I can produce the exact Blowfish bcrypt implementation now (it will be long but I will generate it).
