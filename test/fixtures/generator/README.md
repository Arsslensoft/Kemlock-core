# Generator cases

`cases.json` holds passwords and passphrases the password generator made from
fixed choices, site rules and random bytes. It was written once, by
`test/features/generator/generator_test.dart` with `WRITE_GENERATOR_CASES=1`,
and is never regenerated: the Dart generator (`lib/features/generator`), the
Kotlin one of the Android autofill service and the Swift one of the iOS
extension must each make every password here, byte for byte. The passphrase
cases are Dart's only: AutoFill makes random passwords.

Each case has its `choices` (missing ones take the defaults: 20 characters,
capitals, digits, the symbols `!#%&-_?`, no look-alikes `0 O 1 l I`), its
`rules` in Apple's password rules language when it has some, `bytes` in
hexadecimal, and the `password` expected.

The algorithm (openspec: add-passwords, design decision 5):

1. The sets: small letters always, then capitals, digits and the symbols as
   chosen, each without look-alikes when asked. Under site rules, each set
   keeps what the site allows (what it requires and allows, or any printable
   character when it names neither), and every set the site requires that no
   kept set lies within is added: its characters among those the generator
   uses, else the set without space, else all of it. The length is the
   chosen one, clamped to the site's minimum (at least one per set) and
   maximum. Rules that leave no character, or whose maximum is below that
   minimum, are dropped and the choices used alone.
2. A number below `n` takes one byte when `n` is 256 or less, else two (most
   significant first), drawing again while the value is at or above
   `256 - 256 % n` (or `65536 - 65536 % n`), and is the value modulo `n`.
3. One character from each set, in order; then characters from all the sets
   joined (each character once, in the order they first appear) to the
   length; then a Fisher–Yates shuffle, `i` from the last index down to 1
   swapping with a number below `i + 1`. A character that makes a run longer
   than `max-consecutive` is drawn again from the whole alphabet.
4. A passphrase draws each word below the list's length (EFF's large list,
   in its order), capitalises each when asked, and with a digit draws the
   word's position, then the digit, and puts the digit after that word.
