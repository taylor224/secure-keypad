# secure-keypad Hangul composition, version 1

The Korean keypad (`ko`, LAYOUT.md §3) offers the 2-set (두벌식) jamo: 19 initial/final consonants and
21 vowels, shift giving ㅃ ㅉ ㄸ ㄲ ㅆ ㅒ ㅖ. Taps are transmitted as coordinates like any other key; the
server maps them to compatibility jamo (U+3131–U+3163) and then composes the run of jamo into precomposed
syllables (U+AC00–U+D7A3) exactly as a native 2-set input method would. Composition happens **only on the
server**, inside the decrypt call; clients never see jamo or syllables.

Every server implementation must reproduce `spec/vectors/hangul/compose.json` and the vectors whose text
contains Hangul.

## 1. Automaton

State: `cho` (initial consonant), `jung` (medial vowel), `jong` (final consonant), each a compatibility jamo
or empty. Non-Hangul code points flush the state and pass through unchanged.

`emit()` writes the current state and clears it:

| state | output |
|---|---|
| `cho` + `jung` (+ `jong`) | syllable `0xAC00 + (I(cho) × 21 + V(jung)) × 28 + F(jong)` (`F` = 0 without a final) |
| `cho` only | the consonant |
| `jung` only | the vowel |
| `jong` only | the (compound) consonant, e.g. ㄳ |

Feeding a **consonant** `c` (one of the 19 initials):

| state | action |
|---|---|
| `jung` set, `cho` empty (lone vowel) | emit; `cho = c` |
| `jung` set, `jong` empty | `jong = c` if `c` can be a final (all but ㄸ ㅃ ㅉ), else emit; `cho = c` |
| `jung` set, `jong` set | `jong = combine_final(jong, c)` if that pair exists, else emit; `cho = c` |
| all empty | `cho = c` |
| `cho` only | `jong = combine_final(cho, c)`, `cho` cleared, if the pair exists (ㄱ+ㅅ → ㄳ); else emit; `cho = c` |
| `jong` only | emit; `cho = c` |

Feeding a **vowel** `v`:

| state | action |
|---|---|
| `jung` empty, `jong` set (standalone compound) | split `jong` into `(a, b)`: emit `a`, then `cho = b`, `jung = v` (ㄳ + ㅏ → ㄱ사) |
| `jung` empty otherwise | `jung = v` |
| `jung` set, `jong` empty | `jung = combine_vowel(jung, v)` if the pair exists (ㅗ+ㅏ → ㅘ), else emit; `jung = v` |
| `jung` set, `jong` set | the final moves to the next syllable ("도깨비불"): if `jong` is compound `(a, b)` keep `jong = a`, emit, `cho = b`; else `b = jong`, clear it, emit, `cho = b`. Then `jung = v` |

At the end of the input, emit once more.

## 2. Tables

Initials `I`, in syllable order: ㄱ ㄲ ㄴ ㄷ ㄸ ㄹ ㅁ ㅂ ㅃ ㅅ ㅆ ㅇ ㅈ ㅉ ㅊ ㅋ ㅌ ㅍ ㅎ (U+3131 3132 3134 3137
3138 3139 3141 3142 3143 3145 3146 3147 3148 3149 314A 314B 314C 314D 314E).

Vowels `V`: U+314F ㅏ … U+3163 ㅣ, contiguous in syllable order (`V = cp − 0x314F`).

Finals `F` (index 1..27): ㄱ ㄲ ㄳ ㄴ ㄵ ㄶ ㄷ ㄹ ㄺ ㄻ ㄼ ㄽ ㄾ ㄿ ㅀ ㅁ ㅂ ㅄ ㅅ ㅆ ㅇ ㅈ ㅊ ㅋ ㅌ ㅍ ㅎ
(U+3131 3132 3133 3134 3135 3136 3137 3139 313A 313B 313C 313D 313E 313F 3140 3141 3142 3144 3145 3146 3147
3148 314A 314B 314C 314D 314E).

`combine_vowel`: ㅗ+ㅏ→ㅘ, ㅗ+ㅐ→ㅙ, ㅗ+ㅣ→ㅚ, ㅜ+ㅓ→ㅝ, ㅜ+ㅔ→ㅞ, ㅜ+ㅣ→ㅟ, ㅡ+ㅣ→ㅢ.

`combine_final` (and its inverse `split`): ㄱ+ㅅ→ㄳ, ㄴ+ㅈ→ㄵ, ㄴ+ㅎ→ㄶ, ㄹ+ㄱ→ㄺ, ㄹ+ㅁ→ㄻ, ㄹ+ㅂ→ㄼ,
ㄹ+ㅅ→ㄽ, ㄹ+ㅌ→ㄾ, ㄹ+ㅍ→ㄿ, ㄹ+ㅎ→ㅀ, ㅂ+ㅅ→ㅄ.

## 3. Examples

| taps | result | rule |
|---|---|---|
| ㅎ ㅏ ㄴ ㄱ ㅡ ㄹ | 한글 | finals close syllables |
| ㅎ ㅏ ㄴ ㅏ | 하나 | final carried into the next syllable |
| ㄷ ㅏ ㄹ ㄱ ㅏ | 달가 | compound final split, second half carried |
| ㅂ ㅜ ㅔ ㄹ ㄱ | 뷁 | compound vowel and compound final |
| ㄱ ㅅ | ㄳ | standalone compound consonant |
| ㄱ ㅅ ㅏ | ㄱ사 | standalone compound split by a vowel |
| ㅃ ㅏ ㄸ | 빠ㄸ | ㄸ cannot be a final |
| a b ㅎ ㅏ 1 | ab하1 | other characters pass through |

Backspace on the client removes the last **tap**, i.e. the last jamo, which matches native keyboards where
deleting inside a syllable removes one jamo at a time.

## 4. Decomposition (test helper)

To produce taps for a text, split each syllable into initial, vowel and final; compound vowels and finals
become two taps (the pairs above); ㄲ ㄸ ㅃ ㅆ ㅉ ㅒ ㅖ are single taps on the shift layer. Every syllable
decomposes and recomposes to itself; the reference (`tools/reference/hangul.py`) and the C core test this
exhaustively over all 11 172 syllables.
