import 'package:shieldhash/shieldhash.dart';
import 'package:test/test.dart';

void main() {
  test('hash and compare', () {
    final pw = 'password123';
    final h = hash(pw, rounds: 10);
    expect(compare(pw, h), isTrue);
    expect(compare('bad', h), isFalse);
  });

  test('salt uniqueness', () {
    final a = hash('same', rounds: 12);
    final b = hash('same', rounds: 12);
    expect(a == b, isFalse); // salts should differ so hashes differ
  });

  test('invalid stored format', () {
    expect(compare('a', 'not_a_hash'), isFalse);
  });
}
