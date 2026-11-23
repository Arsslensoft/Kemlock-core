@TestOn('vm')
library;

import 'package:kemlock_core/features/accounts/service_names.dart';
import 'package:test/test.dart';

// Characters outside ASCII are written as escapes, so no editor can normalize them away.

void main() {
  group('sameService', () {
    for (final (a, b) in [
      ('GitHub', 'github'),
      ('GitHub, Inc.', 'GitHub'),
      ('github.com', 'GitHub'),
      ('https://accounts.google.com/', 'Google'),
      ('Epic Games Account', 'Epic Games'),
    ]) {
      test('treats "$a" and "$b" as one service', () {
        expect(sameService(a, b), isTrue);
      });
    }

    test('keeps different services apart', () {
      expect(sameService('GitHub', 'GitLab'), isFalse);
      expect(sameService('Google', 'Google Cloud'), isFalse);
    });
  });

  // The keys the web app's keysFor gives for the same names.
  group('keysFor', () {
    for (final (name, keys) in [
      ('GitHub, Inc.', ['githubinc', 'github', 'github']),
      ('https://accounts.google.com/', ['accountsgooglecom', 'accountsgooglecom', 'googlecom', 'google']),
      ('eu.battle.net', ['eubattlenet', 'eubattlenet', 'battlenet', 'battle']),
      ('shop.example.co.uk', ['shopexamplecouk', 'shopexamplecouk', 'examplecouk', 'example']),
      ('Epic Games Account', ['epicgamesaccount', 'epicgames', 'epicgames']),
      ('Proton AG', ['protonag', 'proton', 'proton']),
      ('Visa', ['visa', 'visa', 'visa']),
      ('GitHub (work)', ['github', 'github', 'github']),
      ('www.GitHub.com', ['githubcom', 'githubcom', 'githubcom', 'github']),
      ('mastodon.social', ['mastodonsocial', 'mastodonsocial', 'mastodonsocial', 'mastodon']),
      ('co.uk', ['couk', 'couk', 'couk', 'co']),
      ('.com', ['com', 'com']),
      ('Z\u{fc}rich Cantonal Bank (ZKB)', ['zurichcantonalbank', 'zurichcantonalbank', 'zurichcantonalbank']),
      ('\u{413}\u{43e}\u{441}\u{443}\u{441}\u{43b}\u{443}\u{433}\u{438} (Gosuslugi)', <String>[]),
      ('', <String>[]),
    ]) {
      test('files "$name" under $keys', () {
        expect(keysFor(name), keys);
      });
    }
  });

  // What the web app's fold, String.normalize('NFD') without the marks, gives for the same names.
  group('fold', () {
    for (final (name, folded) in [
      ('Bitw\u{e4}rden', 'bitwarden'),
      ('  Cr\u{e8}me Br\u{fb}l\u{e9}e  ', 'creme brulee'),
      ('Vi\u{1ec7}t Nam', 'viet nam'),
      ('\u{15e}\u{130}\u{15e}L\u{130}', 'sisli'),
      ('A\u{301}', 'a'), // a combining accent
      ('\u{212a}elvin', 'kelvin'), // the Kelvin sign
      ('\u{212b}ngstr\u{f6}m', 'angstrom'), // the Angstrom sign
      ('\u{386}\u{3bb}\u{3c6}\u{3b1}', '\u{3b1}\u{3bb}\u{3c6}\u{3b1}'), // Greek with tonos
      ('\u{1f71}', '\u{3b1}'), // Greek with oxia
      (
        '\u{39f}\u{394}\u{3a5}\u{3a3}\u{3a3}\u{395}\u{3a5}\u{3a3} \u{39a}\u{391}\u{399}',
        '\u{3bf}\u{3b4}\u{3c5}\u{3c3}\u{3c3}\u{3b5}\u{3c5}\u{3c2} \u{3ba}\u{3b1}\u{3b9}',
      ),
      ('\u{d55c}\u{ad6d}', '\u{1112}\u{1161}\u{11ab}\u{1100}\u{116e}\u{11a8}'), // Hangul syllables
      ('\u{f900}', '\u{8c48}'), // a CJK compatibility ideograph
      ('\u{2f800}', '\u{4e3d}'), // and one outside the BMP
      ('\u{ff27}\u{ff4f}', '\u{ff47}\u{ff4f}'), // compatibility forms are left alone, as NFD leaves them
      ('\u{fb01}nance', '\u{fb01}nance'),
      ('\u{85}x\u{85}', '\u{85}x\u{85}'), // JavaScript's trim() keeps U+0085
      ('\u{3000}x\u{a0}', 'x'),
    ]) {
      test('folds "$name" as JavaScript does', () {
        expect(fold(name), folded);
      });
    }
  });

  group('jsLowerCase', () {
    // What JavaScript's toLowerCase() gives for the same text.
    for (final (text, lower) in [
      ('\u{130}stanbul', 'i\u{307}stanbul'),
      ('\u{3a3}\u{391}\u{3a3}', '\u{3c3}\u{3b1}\u{3c2}'),
      ('\u{3a3}', '\u{3c3}'),
      ('A\u{3a3}B', 'a\u{3c3}b'),
      ('A\u{3a3}.', 'a\u{3c2}.'),
      ('A\u{301}\u{3a3} x', 'a\u{301}\u{3c2} x'),
      ("\u{386}'\u{3a3}", "\u{3ac}'\u{3c2}"),
      ('GitHub', 'github'),
    ]) {
      test('lowers "$text" as JavaScript does', () {
        expect(jsLowerCase(text), lower);
      });
    }
  });

  test('jsTrim removes the white space JavaScript\'s trim() does', () {
    expect(jsTrim(' \t\n\u{a0}\u{2003}\u{3000}\u{feff}x y\u{2028} '), 'x y');
    expect(jsTrim('\u{85}x\u{85}'), '\u{85}x\u{85}');
  });

  test('squash keeps only lowercase letters and digits', () {
    expect(squash('github, inc.'), 'githubinc');
    expect(squash('git-hub inc'), 'githubinc');
    expect(squash('GitHub'), 'itub'); // only after fold has lowercased it
  });
}
