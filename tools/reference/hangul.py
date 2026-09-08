"""Hangul 2-set (두벌식) composition and decomposition, spec/HANGUL.md.

compose(): the jamo a user tapped → the text the server returns (precomposed syllables, standalone jamo
for incomplete runs). decompose(): text → the jamo key sequence that types it (used to build test taps).
"""
CHO = [0x3131, 0x3132, 0x3134, 0x3137, 0x3138, 0x3139, 0x3141, 0x3142, 0x3143, 0x3145,
       0x3146, 0x3147, 0x3148, 0x3149, 0x314A, 0x314B, 0x314C, 0x314D, 0x314E]
JONG = [0, 0x3131, 0x3132, 0x3133, 0x3134, 0x3135, 0x3136, 0x3137, 0x3139, 0x313A, 0x313B, 0x313C, 0x313D,
        0x313E, 0x313F, 0x3140, 0x3141, 0x3142, 0x3144, 0x3145, 0x3146, 0x3147, 0x3148, 0x314A, 0x314B,
        0x314C, 0x314D, 0x314E]
VOWEL_PAIRS = {(0x3157, 0x314F): 0x3158, (0x3157, 0x3150): 0x3159, (0x3157, 0x3163): 0x315A,
               (0x315C, 0x3153): 0x315D, (0x315C, 0x3154): 0x315E, (0x315C, 0x3163): 0x315F,
               (0x3161, 0x3163): 0x3162}
FINAL_PAIRS = {(0x3131, 0x3145): 0x3133, (0x3134, 0x3148): 0x3135, (0x3134, 0x314E): 0x3136,
               (0x3139, 0x3131): 0x313A, (0x3139, 0x3141): 0x313B, (0x3139, 0x3142): 0x313C,
               (0x3139, 0x3145): 0x313D, (0x3139, 0x314C): 0x313E, (0x3139, 0x314D): 0x313F,
               (0x3139, 0x314E): 0x3140, (0x3142, 0x3145): 0x3144}
VOWEL_SPLIT = {v: k for k, v in VOWEL_PAIRS.items()}
FINAL_SPLIT = {v: k for k, v in FINAL_PAIRS.items()}
BASE = 0xAC00


def is_consonant(c: int) -> bool:
    return 0x3131 <= c <= 0x314E


def is_vowel(c: int) -> bool:
    return 0x314F <= c <= 0x3163


class _Composer:
    def __init__(self):
        self.cho = self.jung = self.jong = 0
        self.out = []

    def emit(self):
        if self.cho and self.jung:
            self.out.append(BASE + (CHO.index(self.cho) * 21 + (self.jung - 0x314F)) * 28 + JONG.index(self.jong) if self.jong else
                            BASE + (CHO.index(self.cho) * 21 + (self.jung - 0x314F)) * 28)
        elif self.cho:
            self.out.append(self.cho)
        elif self.jung:
            self.out.append(self.jung)
        elif self.jong:
            self.out.append(self.jong)
        self.cho = self.jung = self.jong = 0

    def feed(self, c: int):
        if is_consonant(c) and c in CHO:
            if self.jung:
                if not self.cho:            # standalone vowel, then a consonant
                    self.emit()
                    self.cho = c
                elif not self.jong:
                    if c in JONG:
                        self.jong = c
                    else:                   # ㄸ ㅃ ㅉ cannot end a syllable
                        self.emit()
                        self.cho = c
                else:
                    f = FINAL_PAIRS.get((self.jong, c))
                    if f:
                        self.jong = f
                    else:
                        self.emit()
                        self.cho = c
            elif not self.cho and not self.jong:
                self.cho = c
            elif self.cho:                  # lone consonant + consonant: standalone compound (ㄱ+ㅅ → ㄳ)
                f = FINAL_PAIRS.get((self.cho, c))
                if f:
                    self.jong, self.cho = f, 0
                else:
                    self.emit()
                    self.cho = c
            else:                           # standalone compound consonant, then another consonant
                self.emit()
                self.cho = c
        elif is_vowel(c):
            if not self.jung:
                if self.jong:               # standalone compound: second half starts the syllable (ㄳ+ㅏ → ㄱ사)
                    a, b = FINAL_SPLIT[self.jong]
                    self.jong = 0
                    self.cho = a
                    self.emit()
                    self.cho = b
                self.jung = c
            elif not self.jong:
                v = VOWEL_PAIRS.get((self.jung, c))
                if v:
                    self.jung = v
                else:
                    self.emit()
                    self.jung = c
            else:                           # final consonant moves to the next syllable (한+ㅏ → 하나)
                if self.jong in FINAL_SPLIT:
                    a, b = FINAL_SPLIT[self.jong]
                    self.jong = a
                    self.emit()
                    self.cho = b
                else:
                    b = self.jong
                    self.jong = 0
                    self.emit()
                    self.cho = b
                self.jung = c
        else:
            self.emit()
            self.out.append(c)


def compose(text: str) -> str:
    c = _Composer()
    for ch in text:
        c.feed(ord(ch))
    c.emit()
    return "".join(chr(x) for x in c.out)


def decompose(text: str) -> str:
    """Text → jamo key presses on a 2-set keyboard (compound vowels/finals become two presses)."""
    out = []
    for ch in text:
        c = ord(ch)
        if BASE <= c <= 0xD7A3:
            idx = c - BASE
            cho, jung, jong = idx // 588, (idx % 588) // 28, idx % 28
            out.append(chr(CHO[cho]))
            v = 0x314F + jung
            out.extend(chr(x) for x in VOWEL_SPLIT.get(v, (v,)))
            if jong:
                f = JONG[jong]
                out.extend(chr(x) for x in FINAL_SPLIT.get(f, (f,)))
        elif c in VOWEL_SPLIT:
            out.extend(chr(x) for x in VOWEL_SPLIT[c])
        elif c in FINAL_SPLIT:
            out.extend(chr(x) for x in FINAL_SPLIT[c])
        else:
            out.append(ch)
    return "".join(out)
