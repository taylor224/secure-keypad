/* JNI shim for libskp. Text arrives as UTF-8 byte arrays; secrets are copied into Java arrays and the
 * native copies are freed immediately. */
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "skp.h"

static void throw_skp(JNIEnv *env, int rc, const char *what) {
    jclass cls = (*env)->FindClass(env, "dev/securekeypad/SkpException");
    if (!cls)
        return; /* pending NoClassDefFoundError */
    jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(ILjava/lang/String;)V");
    if (!ctor)
        return;
    char msg[160];
    snprintf(msg, sizeof msg, "%s (%s)", skp_strerror(rc), what);
    jstring jmsg = (*env)->NewStringUTF(env, msg);
    jobject ex = (*env)->NewObject(env, cls, ctor, (jint)rc, jmsg);
    if (ex)
        (*env)->Throw(env, ex);
}

/* Copies a Java byte[] into a NUL-terminated malloc'd buffer (NULL array → NULL). */
static char *bytes_to_cstr(JNIEnv *env, jbyteArray arr, size_t *len_out) {
    if (!arr) {
        if (len_out)
            *len_out = 0;
        return NULL;
    }
    jsize n = (*env)->GetArrayLength(env, arr);
    char *buf = malloc((size_t)n + 1);
    if (!buf)
        return NULL;
    (*env)->GetByteArrayRegion(env, arr, 0, n, (jbyte *)buf);
    buf[n] = 0;
    if (len_out)
        *len_out = (size_t)n;
    return buf;
}

static void wipe_free(char *p, size_t n) {
    if (p) {
        sodium_memzero(p, n);
        free(p);
    }
}

static jbyteArray new_bytes(JNIEnv *env, const uint8_t *data, size_t len) {
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
    if (arr && len)
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte *)data);
    return arr;
}

static jobjectArray pair(JNIEnv *env, jobject a, jobject b) {
    jclass obj = (*env)->FindClass(env, "java/lang/Object");
    jobjectArray arr = (*env)->NewObjectArray(env, 2, obj, NULL);
    if (!arr)
        return NULL;
    (*env)->SetObjectArrayElement(env, arr, 0, a);
    (*env)->SetObjectArrayElement(env, arr, 1, b);
    return arr;
}

JNIEXPORT jlong JNICALL Java_dev_securekeypad_Native_init(JNIEnv *env, jclass cls, jbyteArray path, jbyteArray key,
                                                          jint ttl, jint cap) {
    (void)cls;
    size_t plen = 0, klen = 0;
    char *p = bytes_to_cstr(env, path, &plen);
    char *k = bytes_to_cstr(env, key, &klen);
    if ((path && !p) || (key && !k)) {
        wipe_free(p, plen);
        wipe_free(k, klen);
        throw_skp(env, SKP_ERR_NOMEM, "init");
        return 0;
    }
    skp_config cfg = {0};
    cfg.master_key_path = p;
    cfg.master_key = k;
    cfg.master_key_len = klen;
    cfg.default_ttl_sec = ttl > 0 ? (uint32_t)ttl : 0;
    cfg.max_len_cap = cap > 0 ? (uint32_t)cap : 0;
    skp_ctx *ctx = NULL;
    int rc = skp_init(&ctx, &cfg);
    wipe_free(p, plen);
    wipe_free(k, klen);
    if (rc) {
        throw_skp(env, rc, "init");
        return 0;
    }
    return (jlong)(intptr_t)ctx;
}

JNIEXPORT void JNICALL Java_dev_securekeypad_Native_free(JNIEnv *env, jclass cls, jlong h) {
    (void)env;
    (void)cls;
    skp_free((skp_ctx *)(intptr_t)h);
}

JNIEXPORT jstring JNICALL Java_dev_securekeypad_Native_version(JNIEnv *env, jclass cls) {
    (void)cls;
    return (*env)->NewStringUTF(env, skp_version());
}

JNIEXPORT jstring JNICALL Java_dev_securekeypad_Native_publicKey(JNIEnv *env, jclass cls, jlong h) {
    (void)cls;
    char b64[SKP_PUBLIC_KEY_B64_CAP];
    int rc = skp_public_key((const skp_ctx *)(intptr_t)h, b64, sizeof b64);
    if (rc) {
        throw_skp(env, rc, "publicKey");
        return NULL;
    }
    return (*env)->NewStringUTF(env, b64);
}

JNIEXPORT jstring JNICALL Java_dev_securekeypad_Native_keyId(JNIEnv *env, jclass cls, jlong h) {
    (void)cls;
    char kid[SKP_KID_CAP];
    int rc = skp_key_id((const skp_ctx *)(intptr_t)h, kid, sizeof kid);
    if (rc) {
        throw_skp(env, rc, "keyId");
        return NULL;
    }
    return (*env)->NewStringUTF(env, kid);
}

JNIEXPORT jstring JNICALL Java_dev_securekeypad_Native_keygen(JNIEnv *env, jclass cls) {
    (void)cls;
    char b64[64];
    int rc = skp_keygen_b64(b64, sizeof b64);
    if (rc) {
        throw_skp(env, rc, "keygen");
        return NULL;
    }
    jstring s = (*env)->NewStringUTF(env, b64);
    sodium_memzero(b64, sizeof b64);
    return s;
}

JNIEXPORT jobjectArray JNICALL Java_dev_securekeypad_Native_createSession(JNIEnv *env, jclass cls, jlong h,
                                                                          jbyteArray req, jbyteArray jctx,
                                                                          jbyteArray jlayout, jbyteArray jblank,
                                                                          jint ttl, jint max_len, jbyteArray jlangs) {
    (void)cls;
    size_t rlen = 0, clen = 0, llen = 0, blen = 0, glen = 0;
    char *r = bytes_to_cstr(env, req, &rlen);
    char *c = bytes_to_cstr(env, jctx, &clen);
    char *l = bytes_to_cstr(env, jlayout, &llen);
    char *b = bytes_to_cstr(env, jblank, &blen);
    char *g = bytes_to_cstr(env, jlangs, &glen);
    jobjectArray out = NULL;
    if (!r) {
        throw_skp(env, SKP_ERR_INVALID_ARG, "request");
        goto done;
    }
    skp_session_opts opts = {c, l, b, ttl > 0 ? (uint32_t)ttl : 0, max_len > 0 ? (uint32_t)max_len : 0, g};
    skp_buf resp = {0}, sealed = {0};
    int rc = skp_session_create((const skp_ctx *)(intptr_t)h, r, rlen, &opts, &resp, &sealed);
    if (rc) {
        throw_skp(env, rc, "createSession");
        goto done;
    }
    out = pair(env, new_bytes(env, resp.data, resp.len), new_bytes(env, sealed.data, sealed.len));
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
done:
    wipe_free(r, rlen);
    wipe_free(c, clen);
    wipe_free(l, llen);
    wipe_free(b, blen);
    wipe_free(g, glen);
    return out;
}

JNIEXPORT jobjectArray JNICALL Java_dev_securekeypad_Native_relayout(JNIEnv *env, jclass cls, jlong h,
                                                                     jbyteArray jsealed, jbyteArray req) {
    (void)cls;
    size_t slen = 0, rlen = 0;
    char *s = bytes_to_cstr(env, jsealed, &slen);
    char *r = bytes_to_cstr(env, req, &rlen);
    jobjectArray out = NULL;
    if (!s || !r) {
        throw_skp(env, SKP_ERR_INVALID_ARG, "relayout");
        goto done;
    }
    skp_buf resp = {0}, sealed2 = {0};
    int rc = skp_session_relayout((const skp_ctx *)(intptr_t)h, (const uint8_t *)s, slen, r, rlen, &resp, &sealed2);
    if (rc) {
        throw_skp(env, rc, "relayout");
        goto done;
    }
    out = pair(env, new_bytes(env, resp.data, resp.len), new_bytes(env, sealed2.data, sealed2.len));
    skp_buf_free(&resp);
    skp_buf_free(&sealed2);
done:
    wipe_free(s, slen);
    wipe_free(r, rlen);
    return out;
}

JNIEXPORT jbyteArray JNICALL Java_dev_securekeypad_Native_decrypt(JNIEnv *env, jclass cls, jlong h, jbyteArray jsealed,
                                                                  jbyteArray payload, jbyteArray jctx) {
    (void)cls;
    size_t slen = 0, plen = 0, clen = 0;
    char *s = bytes_to_cstr(env, jsealed, &slen);
    char *p = bytes_to_cstr(env, payload, &plen);
    char *c = bytes_to_cstr(env, jctx, &clen);
    jbyteArray out = NULL;
    if (!s || !p) {
        throw_skp(env, SKP_ERR_INVALID_ARG, "decrypt");
        goto done;
    }
    skp_secret *sec = NULL;
    int rc = skp_session_decrypt((const skp_ctx *)(intptr_t)h, (const uint8_t *)s, slen, p, plen, c, &sec);
    if (rc) {
        throw_skp(env, rc, "decrypt");
        goto done;
    }
    out = new_bytes(env, skp_secret_bytes(sec), skp_secret_len(sec));
    skp_secret_free(sec);
done:
    wipe_free(s, slen);
    wipe_free(p, plen);
    wipe_free(c, clen);
    return out;
}

JNIEXPORT jobjectArray JNICALL Java_dev_securekeypad_Native_sessionInfo(JNIEnv *env, jclass cls, jlong h,
                                                                        jbyteArray jsealed) {
    (void)cls;
    size_t slen = 0;
    char *s = bytes_to_cstr(env, jsealed, &slen);
    if (!s) {
        throw_skp(env, SKP_ERR_INVALID_ARG, "sessionInfo");
        return NULL;
    }
    int64_t expires = 0;
    char sid[64];
    int rc = skp_session_info((const skp_ctx *)(intptr_t)h, (const uint8_t *)s, slen, &expires, sid, sizeof sid);
    wipe_free(s, slen);
    if (rc) {
        throw_skp(env, rc, "sessionInfo");
        return NULL;
    }
    jclass longCls = (*env)->FindClass(env, "java/lang/Long");
    jmethodID valueOf = (*env)->GetStaticMethodID(env, longCls, "valueOf", "(J)Ljava/lang/Long;");
    jobject jexp = (*env)->CallStaticObjectMethod(env, longCls, valueOf, (jlong)expires);
    return pair(env, jexp, (*env)->NewStringUTF(env, sid));
}
