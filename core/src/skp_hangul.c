/* Hangul 2-set (두벌식) composition, spec/HANGUL.md. Turns the jamo the user tapped into precomposed
 * syllables the way native Korean keyboards do: initial + medial (+ final), compound medials and finals,
 * and the "dokkaebi-bul" carry of a final consonant into the next syllable when a vowel follows.
 * Non-Hangul code points pass through and terminate the current syllable. */
#include "skp_internal.h"

#define CJ_CONS_FIRST 0x3131 /* ㄱ */
#define CJ_CONS_LAST 0x314E  /* ㅎ */
#define CJ_VOWEL_FIRST 0x314F /* ㅏ */
#define CJ_VOWEL_LAST 0x3163  /* ㅣ */
#define SYLLABLE_BASE 0xAC00

/* initial consonants (19) in syllable order */
static const uint32_t CHO[19] = {0x3131, 0x3132, 0x3134, 0x3137, 0x3138, 0x3139, 0x3141, 0x3142, 0x3143, 0x3145,
                                 0x3146, 0x3147, 0x3148, 0x3149, 0x314A, 0x314B, 0x314C, 0x314D, 0x314E};
/* final consonants (27) in syllable order, index 0 = none */
static const uint32_t JONG[28] = {0,      0x3131, 0x3132, 0x3133, 0x3134, 0x3135, 0x3136, 0x3137, 0x3139, 0x313A,
                                  0x313B, 0x313C, 0x313D, 0x313E, 0x313F, 0x3140, 0x3141, 0x3142, 0x3144, 0x3145,
                                  0x3146, 0x3147, 0x3148, 0x314A, 0x314B, 0x314C, 0x314D, 0x314E};
/* compound medials: first + second → combined */
static const uint32_t VOWEL_PAIRS[7][3] = {{0x3157, 0x314F, 0x3158}, {0x3157, 0x3150, 0x3159}, {0x3157, 0x3163, 0x315A},
                                           {0x315C, 0x3153, 0x315D}, {0x315C, 0x3154, 0x315E}, {0x315C, 0x3163, 0x315F},
                                           {0x3161, 0x3163, 0x3162}};
/* compound finals: first + second → combined */
static const uint32_t FINAL_PAIRS[11][3] = {{0x3131, 0x3145, 0x3133}, {0x3134, 0x3148, 0x3135}, {0x3134, 0x314E, 0x3136},
                                            {0x3139, 0x3131, 0x313A}, {0x3139, 0x3141, 0x313B}, {0x3139, 0x3142, 0x313C},
                                            {0x3139, 0x3145, 0x313D}, {0x3139, 0x314C, 0x313E}, {0x3139, 0x314D, 0x313F},
                                            {0x3139, 0x314E, 0x3140}, {0x3142, 0x3145, 0x3144}};

static int is_consonant(uint32_t c) { return c >= CJ_CONS_FIRST && c <= CJ_CONS_LAST; }
static int is_vowel(uint32_t c) { return c >= CJ_VOWEL_FIRST && c <= CJ_VOWEL_LAST; }

static int cho_index(uint32_t c) {
    for (int i = 0; i < 19; i++)
        if (CHO[i] == c)
            return i;
    return -1;
}

static int jong_index(uint32_t c) {
    for (int i = 1; i < 28; i++)
        if (JONG[i] == c)
            return i;
    return 0;
}

static uint32_t combine_vowel(uint32_t a, uint32_t b) {
    for (int i = 0; i < 7; i++)
        if (VOWEL_PAIRS[i][0] == a && VOWEL_PAIRS[i][1] == b)
            return VOWEL_PAIRS[i][2];
    return 0;
}

static uint32_t combine_final(uint32_t a, uint32_t b) {
    for (int i = 0; i < 11; i++)
        if (FINAL_PAIRS[i][0] == a && FINAL_PAIRS[i][1] == b)
            return FINAL_PAIRS[i][2];
    return 0;
}

static int split_final(uint32_t c, uint32_t *a, uint32_t *b) {
    for (int i = 0; i < 11; i++)
        if (FINAL_PAIRS[i][2] == c) {
            *a = FINAL_PAIRS[i][0];
            *b = FINAL_PAIRS[i][1];
            return 1;
        }
    return 0;
}

typedef struct {
    uint32_t cho, jung, jong; /* compatibility jamo code points, 0 = empty */
    uint32_t *out;
    size_t n;
} composer;

static void emit(composer *s) {
    if (s->cho && s->jung) {
        int ci = cho_index(s->cho), ji = jong_index(s->jong);
        s->out[s->n++] = SYLLABLE_BASE + ((uint32_t)ci * 21 + (s->jung - CJ_VOWEL_FIRST)) * 28 + (uint32_t)ji;
    } else if (s->cho) {
        s->out[s->n++] = s->cho;
    } else if (s->jung) {
        s->out[s->n++] = s->jung;
    } else if (s->jong) {
        s->out[s->n++] = s->jong;
    }
    s->cho = s->jung = s->jong = 0;
}

static void feed(composer *s, uint32_t c) {
    if (is_consonant(c) && cho_index(c) >= 0) {
        if (s->jung) {
            if (!s->cho) { /* standalone vowel, then a consonant */
                emit(s);
                s->cho = c;
            } else if (!s->jong) {
                if (jong_index(c))
                    s->jong = c;
                else { /* ㄸ ㅃ ㅉ cannot end a syllable */
                    emit(s);
                    s->cho = c;
                }
            } else {
                uint32_t f = combine_final(s->jong, c);
                if (f)
                    s->jong = f;
                else {
                    emit(s);
                    s->cho = c;
                }
            }
        } else if (!s->cho && !s->jong) {
            s->cho = c;
        } else if (s->cho) { /* consonant after a lone consonant: standalone compound (ㄱ+ㅅ → ㄳ) or restart */
            uint32_t f = combine_final(s->cho, c);
            if (f) {
                s->jong = f;
                s->cho = 0;
            } else {
                emit(s);
                s->cho = c;
            }
        } else { /* standalone compound consonant, then another consonant */
            emit(s);
            s->cho = c;
        }
    } else if (is_vowel(c)) {
        if (!s->jung) {
            if (s->jong) { /* standalone compound consonant: its second half starts the syllable (ㄳ+ㅏ → ㄱ사) */
                uint32_t a, b;
                split_final(s->jong, &a, &b);
                s->jong = 0;
                s->cho = a;
                emit(s);
                s->cho = b;
            }
            s->jung = c;
        } else if (!s->jong) {
            uint32_t v = combine_vowel(s->jung, c);
            if (v)
                s->jung = v;
            else {
                emit(s);
                s->jung = c;
            }
        } else { /* final consonant moves to the next syllable (한+ㅏ → 하나, 닭+ㅏ → 달가) */
            uint32_t a, b;
            if (split_final(s->jong, &a, &b)) {
                s->jong = a;
                emit(s);
                s->cho = b;
            } else {
                b = s->jong;
                s->jong = 0;
                emit(s);
                s->cho = b;
            }
            s->jung = c;
        }
    } else {
        emit(s);
        s->out[s->n++] = c;
    }
}

size_t skp_hangul_compose(const uint32_t *in, size_t n, uint32_t *out) {
    composer s = {0, 0, 0, out, 0};
    for (size_t i = 0; i < n; i++)
        feed(&s, in[i]);
    emit(&s);
    size_t len = s.n;
    sodium_memzero(&s, sizeof s);
    return len;
}
