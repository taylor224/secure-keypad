// N-API binding for libskp. Thin and synchronous: every call maps to one C call, every C buffer is
// released before returning, and decrypted bytes are copied once into a JS Buffer the caller wipes.
#include <napi.h>
#include <cstring>
#include <string>
#include <vector>
#include "skp.h"

namespace {

Napi::Error make_error(Napi::Env env, int code, const char *what) {
    std::string msg = std::string(what) + ": " + skp_strerror(code);
    Napi::Error err = Napi::Error::New(env, msg);
    err.Set("code", Napi::Number::New(env, code));
    return err;
}

std::string opt_string(const Napi::Object &o, const char *key) {
    if (!o.Has(key))
        return "";
    Napi::Value v = o.Get(key);
    if (v.IsUndefined() || v.IsNull())
        return "";
    if (!v.IsString())
        throw Napi::TypeError::New(o.Env(), std::string(key) + " must be a string");
    return v.As<Napi::String>().Utf8Value();
}

uint32_t opt_uint(const Napi::Object &o, const char *key) {
    if (!o.Has(key))
        return 0;
    Napi::Value v = o.Get(key);
    if (v.IsUndefined() || v.IsNull())
        return 0;
    if (!v.IsNumber())
        throw Napi::TypeError::New(o.Env(), std::string(key) + " must be a number");
    double d = v.As<Napi::Number>().DoubleValue();
    if (d < 0 || d > 4294967295.0)
        throw Napi::RangeError::New(o.Env(), std::string(key) + " out of range");
    return static_cast<uint32_t>(d);
}

std::string json_arg(const Napi::CallbackInfo &info, size_t i, const char *what) {
    if (info.Length() <= i || !info[i].IsString())
        throw Napi::TypeError::New(info.Env(), std::string(what) + " must be a JSON string");
    return info[i].As<Napi::String>().Utf8Value();
}

Napi::Buffer<uint8_t> buffer_arg(const Napi::CallbackInfo &info, size_t i, const char *what) {
    if (info.Length() <= i || !info[i].IsBuffer())
        throw Napi::TypeError::New(info.Env(), std::string(what) + " must be a Buffer");
    return info[i].As<Napi::Buffer<uint8_t>>();
}

class Server : public Napi::ObjectWrap<Server> {
  public:
    static Napi::Function Init(Napi::Env env) {
        return DefineClass(env, "Server",
                           {InstanceMethod("publicKey", &Server::PublicKey), InstanceMethod("keyId", &Server::KeyId),
                            InstanceMethod("createSession", &Server::CreateSession),
                            InstanceMethod("relayout", &Server::Relayout), InstanceMethod("decrypt", &Server::Decrypt),
                            InstanceMethod("sessionInfo", &Server::SessionInfo), InstanceMethod("close", &Server::Close)});
    }

    Server(const Napi::CallbackInfo &info) : Napi::ObjectWrap<Server>(info) {
        Napi::Env env = info.Env();
        if (info.Length() < 1 || !info[0].IsObject())
            throw Napi::TypeError::New(env, "options object required");
        Napi::Object o = info[0].As<Napi::Object>();
        std::string path = opt_string(o, "masterKeyPath");
        std::string key;
        std::vector<uint8_t> raw;
        if (o.Has("masterKey") && !o.Get("masterKey").IsUndefined() && !o.Get("masterKey").IsNull()) {
            Napi::Value v = o.Get("masterKey");
            if (v.IsTypedArray()) {
                Napi::TypedArray ta = v.As<Napi::TypedArray>();
                const uint8_t *p = static_cast<const uint8_t *>(ta.ArrayBuffer().Data()) + ta.ByteOffset();
                raw.assign(p, p + ta.ByteLength());
            } else if (v.IsString()) {
                key = v.As<Napi::String>().Utf8Value();
            } else {
                throw Napi::TypeError::New(env, "masterKey must be a string or Buffer");
            }
        }
        std::string font_ios = opt_string(o, "fontIosPath"), font_material = opt_string(o, "fontMaterialPath"),
                    font_fallback = opt_string(o, "fontFallbackPath");
        skp_config cfg;
        std::memset(&cfg, 0, sizeof cfg);
        cfg.master_key_path = path.empty() ? nullptr : path.c_str();
        if (!raw.empty()) {
            cfg.master_key = reinterpret_cast<const char *>(raw.data());
            cfg.master_key_len = raw.size();
        } else if (!key.empty()) {
            cfg.master_key = key.c_str();
        }
        cfg.font_ios_path = font_ios.empty() ? nullptr : font_ios.c_str();
        cfg.font_material_path = font_material.empty() ? nullptr : font_material.c_str();
        cfg.font_fallback_path = font_fallback.empty() ? nullptr : font_fallback.c_str();
        cfg.default_ttl_sec = opt_uint(o, "defaultTtl");
        cfg.max_len_cap = opt_uint(o, "maxLenCap");
        int rc = skp_init(&ctx_, &cfg);
        if (!key.empty())
            std::fill(key.begin(), key.end(), 0);
        if (!raw.empty())
            std::fill(raw.begin(), raw.end(), 0);
        if (rc != SKP_OK)
            throw make_error(env, rc, "init");
    }

    ~Server() override { skp_free(ctx_); }

  private:
    skp_ctx *ctx_ = nullptr;

    void require_open(Napi::Env env) {
        if (!ctx_)
            throw Napi::Error::New(env, "server is closed");
    }

    Napi::Value PublicKey(const Napi::CallbackInfo &info) {
        require_open(info.Env());
        char b64[SKP_PUBLIC_KEY_B64_CAP];
        int rc = skp_public_key(ctx_, b64, sizeof b64);
        if (rc)
            throw make_error(info.Env(), rc, "publicKey");
        return Napi::String::New(info.Env(), b64);
    }

    Napi::Value KeyId(const Napi::CallbackInfo &info) {
        require_open(info.Env());
        char kid[SKP_KID_CAP];
        skp_key_id(ctx_, kid, sizeof kid);
        return Napi::String::New(info.Env(), kid);
    }

    Napi::Value CreateSession(const Napi::CallbackInfo &info) {
        Napi::Env env = info.Env();
        require_open(env);
        std::string req = json_arg(info, 0, "request");
        skp_session_opts opts;
        std::memset(&opts, 0, sizeof opts);
        std::string ctx, layout, blank, languages;
        if (info.Length() > 1 && info[1].IsObject()) {
            Napi::Object o = info[1].As<Napi::Object>();
            ctx = opt_string(o, "ctx");
            layout = opt_string(o, "layout");
            blank = opt_string(o, "blank");
            languages = opt_string(o, "languages");
            opts.ttl_sec = opt_uint(o, "ttl");
            opts.max_len = opt_uint(o, "maxLen");
        }
        opts.ctx = ctx.empty() ? nullptr : ctx.c_str();
        opts.layout = layout.empty() ? nullptr : layout.c_str();
        opts.blank = blank.empty() ? nullptr : blank.c_str();
        opts.languages = languages.empty() ? nullptr : languages.c_str();
        skp_buf resp = {nullptr, 0}, sealed = {nullptr, 0};
        int rc = skp_session_create(ctx_, req.c_str(), req.size(), &opts, &resp, &sealed);
        if (rc)
            throw make_error(env, rc, "createSession");
        Napi::Object out = Napi::Object::New(env);
        out.Set("response", Napi::String::New(env, reinterpret_cast<const char *>(resp.data), resp.len));
        out.Set("sealed", Napi::Buffer<uint8_t>::Copy(env, sealed.data, sealed.len));
        skp_buf_free(&resp);
        skp_buf_free(&sealed);
        return out;
    }

    Napi::Value Relayout(const Napi::CallbackInfo &info) {
        Napi::Env env = info.Env();
        require_open(env);
        Napi::Buffer<uint8_t> sealed = buffer_arg(info, 0, "sealed");
        std::string req = json_arg(info, 1, "request");
        skp_buf resp = {nullptr, 0}, out_sealed = {nullptr, 0};
        int rc = skp_session_relayout(ctx_, sealed.Data(), sealed.Length(), req.c_str(), req.size(), &resp, &out_sealed);
        if (rc)
            throw make_error(env, rc, "relayout");
        Napi::Object out = Napi::Object::New(env);
        out.Set("response", Napi::String::New(env, reinterpret_cast<const char *>(resp.data), resp.len));
        out.Set("sealed", Napi::Buffer<uint8_t>::Copy(env, out_sealed.data, out_sealed.len));
        skp_buf_free(&resp);
        skp_buf_free(&out_sealed);
        return out;
    }

    Napi::Value Decrypt(const Napi::CallbackInfo &info) {
        Napi::Env env = info.Env();
        require_open(env);
        Napi::Buffer<uint8_t> sealed = buffer_arg(info, 0, "sealed");
        std::string payload = json_arg(info, 1, "payload");
        std::string ctx;
        if (info.Length() > 2 && info[2].IsString())
            ctx = info[2].As<Napi::String>().Utf8Value();
        skp_secret *secret = nullptr;
        int rc = skp_session_decrypt(ctx_, sealed.Data(), sealed.Length(), payload.c_str(), payload.size(),
                                     ctx.empty() ? nullptr : ctx.c_str(), &secret);
        if (rc)
            throw make_error(env, rc, "decrypt");
        Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::Copy(env, skp_secret_bytes(secret), skp_secret_len(secret));
        skp_secret_free(secret);
        return out;
    }

    Napi::Value SessionInfo(const Napi::CallbackInfo &info) {
        Napi::Env env = info.Env();
        require_open(env);
        Napi::Buffer<uint8_t> sealed = buffer_arg(info, 0, "sealed");
        int64_t expires = 0;
        char sid[64];
        int rc = skp_session_info(ctx_, sealed.Data(), sealed.Length(), &expires, sid, sizeof sid);
        if (rc)
            throw make_error(env, rc, "sessionInfo");
        Napi::Object out = Napi::Object::New(env);
        out.Set("expires", Napi::Number::New(env, static_cast<double>(expires)));
        out.Set("sid", Napi::String::New(env, sid));
        return out;
    }

    Napi::Value Close(const Napi::CallbackInfo &info) {
        skp_free(ctx_);
        ctx_ = nullptr;
        return info.Env().Undefined();
    }
};

Napi::Value Keygen(const Napi::CallbackInfo &info) {
    char b64[64];
    int rc = skp_keygen_b64(b64, sizeof b64);
    if (rc)
        throw make_error(info.Env(), rc, "keygen");
    Napi::String s = Napi::String::New(info.Env(), b64);
    std::memset(b64, 0, sizeof b64);
    return s;
}

Napi::Value Version(const Napi::CallbackInfo &info) { return Napi::String::New(info.Env(), skp_version()); }

#ifdef SKP_TESTING
static uint8_t g_s_sk[32], g_sid[16], g_seed[32], g_nonce24[24];
static skp_test_hooks g_hooks;

static bool copy_hook(const Napi::Object &o, const char *key, uint8_t *dst, size_t len) {
    if (!o.Has(key) || o.Get(key).IsUndefined() || o.Get(key).IsNull())
        return false;
    Napi::Buffer<uint8_t> b = o.Get(key).As<Napi::Buffer<uint8_t>>();
    if (b.Length() != len)
        throw Napi::RangeError::New(o.Env(), std::string(key) + " has the wrong length");
    std::memcpy(dst, b.Data(), len);
    return true;
}

Napi::Value SetTestHooks(const Napi::CallbackInfo &info) {
    if (info.Length() < 1 || info[0].IsNull() || info[0].IsUndefined()) {
        skp_test_set_hooks(nullptr);
        return info.Env().Undefined();
    }
    Napi::Object o = info[0].As<Napi::Object>();
    std::memset(&g_hooks, 0, sizeof g_hooks);
    if (copy_hook(o, "sSk", g_s_sk, 32))
        g_hooks.s_sk = g_s_sk;
    if (copy_hook(o, "sid", g_sid, 16))
        g_hooks.sid = g_sid;
    if (copy_hook(o, "seed", g_seed, 32))
        g_hooks.seed = g_seed;
    if (copy_hook(o, "nonce24", g_nonce24, 24))
        g_hooks.nonce24 = g_nonce24;
    g_hooks.now = static_cast<int64_t>(opt_uint(o, "now"));
    g_hooks.no_render = o.Has("noRender") && o.Get("noRender").ToBoolean().Value() ? 1 : 0;
    skp_test_set_hooks(&g_hooks);
    return info.Env().Undefined();
}
#endif

Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
    exports.Set("Server", Server::Init(env));
    exports.Set("keygen", Napi::Function::New(env, Keygen));
    exports.Set("version", Napi::Function::New(env, Version));
#ifdef SKP_TESTING
    exports.Set("setTestHooks", Napi::Function::New(env, SetTestHooks));
    exports.Set("testing", Napi::Boolean::New(env, true));
#else
    exports.Set("testing", Napi::Boolean::New(env, false));
#endif
    return exports;
}

} // namespace

NODE_API_MODULE(skp, InitModule)
