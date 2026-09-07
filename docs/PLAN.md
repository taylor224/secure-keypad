# secure-keypad — 설계 및 실행 계획 (v0.1 초안)

작성일: 2026-09-07 · 상태: 검토 대기 · 작업명: `secure-keypad` (접두어 `skp`)

## 0. 한 줄 요약

서버가 세션마다 **무작위 배열**의 키패드를 만들고, **글자 이미지(타일)만 암호화**해서 내려준다.
클라이언트는 iOS / Android 기본 키보드와 같은 모양의 틀(chrome)을 **직접 네이티브로 그리고** 그 위에 타일을 붙인다.
사용자가 누르면 **터치 좌표만 암호화**해서 올리고, 서버 SDK(C 코어 + Java / Python / Node 바인딩)가 좌표를 글자로 복원한다.
복원이 끝난 세션의 배열·키·값은 **잠긴 메모리에서 즉시 소거**된다.

---

## 1. 목표와 비목표

### 1.1 목표 (v1.0)

| # | 요구사항 | 계획 |
|---|---|---|
| G1 | 클라이언트는 입력된 글자를 알 수 없어야 함 | 서버만 아는 세션별 무작위 배열 + 좌표 전송. 클라이언트에는 문자 코드·문자 식별자가 절대 내려가지 않음 |
| G2 | 키패드 이미지·좌표 모두 암호화 | 세션마다 새 키(X25519 ECDH + HKDF) + ChaCha20-Poly1305 AEAD. TLS 위에 앱 레이어 E2E 암호화 |
| G3 | 호출마다 암호 키 변경 | 서버·클라이언트 모두 세션마다 ephemeral 키쌍 생성. 서버 ephemeral 개인키는 키 유도 직후 폐기(전방향 비밀성) |
| G4 | 서버 마스터 키를 파일 또는 텍스트로 보관, init 시 경로 또는 값 입력 | `skp-keygen` CLI + `masterKeyPath` / `masterKey` / 환경변수 |
| G5 | 복호화 끝난 세션 데이터는 디스크·메모리 어디에도 남지 않음 | 코어는 무상태(sealed blob), 비밀은 `sodium_malloc`(mlock + guard page)에서만 존재, `sodium_memzero`로 소거. 개발자가 `keep` 옵션을 켠 경우만 유지 |
| G6 | 일반(QWERTY) 키보드 + 숫자 키패드 | QWERTY 4 레이어(소문자 / 대문자 / 숫자·기호 / 기호2) + 3×4 숫자 패드 |
| G7 | iOS / Android 기본 키보드와 비슷한 UI/UX, 눌림 피드백 | 플랫폼별 메트릭 테이블 + 눌림 하이라이트·팝업 버블·햅틱·클릭음 |
| G8 | 모바일에서 찌그러짐 없음 | 서버가 클라이언트 실제 픽셀 크기(`w × dpr`)에 맞춰 타일을 렌더링, 클라이언트는 비트맵을 절대 스케일하지 않음 |
| G9 | 플랫폼: 웹, 모바일웹, iOS, Android | `@secure-keypad/web`, `@secure-keypad/react`, Swift Package, Android AAR |
| G10 | 서버: C 빌드 + Java / Python / NodeJS 라이브러리 | `libskp`(C11, libsodium 정적 링크) + JNI / cffi / N-API 바인딩, 각 레지스트리에 prebuilt 배포 |
| G11 | **배열 무작위화 옵션** (추가 요청) | 서버 옵션 `layout: "fixed" \| "shuffle" \| "full"`, 숫자패드 `blank: "fixed" \| "random"`, v1.1에 "재배열" 키·키 입력마다 재배열 |

### 1.2 비목표 (v1.0에서 제외, 로드맵에 기록)

- 한글(2벌식) 입력·조합 — 서버 측 오토마타가 필요, v2
- 자동완성·예측·이모지·다국어 라벨
- 시스템 IME 대체(InputMethodService / Keyboard Extension) — 앱 내 키패드만 제공
- 스트리밍 모드(키 하나마다 서버 전송), 마지막 글자 잠깐 보여주기 — v1.1
- 데스크톱 네이티브 앱 — 웹 SDK로 커버(Electron 등)
- 루팅·탈옥·디버거 탐지 — 훅만 제공, 판단은 통합사 몫

---

## 2. 위협 모델과 보안 원칙

이 절은 요구사항 중 가장 중요한 부분이므로, 무엇을 막고 무엇을 막지 못하는지 명확히 적는다.

### 2.1 막는 것

| 공격자 | 시나리오 | 대응 |
|---|---|---|
| 키로거 / 악성 IME / 접근성 서비스 | 시스템 키보드 입력 훔치기 | 시스템 키보드를 아예 쓰지 않음. 접근성 트리에 키 라벨 노출 없음 |
| 클라이언트 메모리 덤프·변조 | 앱 메모리에서 평문 찾기 | 평문 문자·문자 코드·좌표→문자 매핑이 클라이언트에 존재하지 않음. 남는 것은 (배열 없이는 무의미한) 좌표와 세션 키뿐 |
| 네트워크 관찰자 / TLS 종단 프록시 / WAF / APM 로그 | 요청·응답 본문 열람 | 이미지·좌표 모두 세션 키로 AEAD 암호화. 본문 길이도 고정(패딩)이라 입력 길이 누설 없음 |
| 중간자(MITM, TLS 뚫린 경우 포함) | 배열이 알려진 가짜 키패드로 바꿔치기 | 서버 장기 Ed25519 키로 ephemeral 공개키·세션 ID·암호문 해시에 서명. 클라이언트가 공개키 핀 설정 시 검증 |
| 재전송 / 교차 사용자 재사용 | 훔친 암호문 재사용 | 세션 1회용(복호화 시 파기), 카운터 nonce, 통합사 컨텍스트(`ctx`)를 AAD와 sealed blob에 바인딩 |
| 서버 측 로그·저장소·코어 덤프 | 배열·세션 키가 디스크에 남음 | 저장소에는 마스터 파생 키로 봉인된 암호문만. 평문은 create / decrypt 호출 동안 mlock 메모리에만 존재 후 소거. 로그에 비밀 출력 없음 |
| 서버 장기 키 유출(사후) | 과거 캡처 트래픽 복호화 | 세션 키는 ephemeral-ephemeral ECDH로 유도 → 전방향 비밀성. 장기 키는 서명 전용 |
| 화면 캡처 / 녹화(플랫폼이 허용하는 범위) | 키패드 화면 촬영 | Android `FLAG_SECURE`, iOS `isCaptured` 감지 시 키패드 가림·경고, 앱 전환 스냅샷 전 가림 |

### 2.2 막지 못하는 것 (솔직하게)

- **OS 자체가 완전히 장악된 기기**(루팅 후 화면 프레임버퍼 + 터치 이벤트를 동시에 가로채는 공격자)는 이미지와 좌표를 합쳐 입력을 재구성할 수 있다. 시각적 키패드의 근본 한계이며, 어떤 보안 키패드도 이 경우를 막지 못한다. 우리는 이 공격의 비용을 최대한 높인다(무작위 배열, 문자 식별자 부재, 캡처 차단, 무결성 힌트).
- 웹은 JS가 검사 가능한 환경이므로 네이티브보다 약하다. 그래도 **평문이 브라우저에 존재한 적이 없다**는 성질은 동일하게 유지된다.
- `layout: "fixed"`(배열 고정)를 선택하면 좌표만으로 글자가 기하학적으로 추론된다. 이 모드는 키로거·네트워크 방어만 제공하며, 문서와 로그 경고로 명시한다.

### 2.3 설계 불변식 (모든 구현이 지켜야 하는 규칙)

- **I1. 문자 식별 정보는 서버 밖으로 나가지 않는다.** 응답에는 문자 코드, 문자별 고정 ID, 문자별 이미지 크기가 없다. 키는 항상 **공간 순서(행 우선)**로 번호를 매기고, 타일은 그 순서대로 **단일 스프라이트 시트**에 담는다. (타일을 낱개 PNG로 보내면 파일 크기가 글자를 지문화하므로 금지)
- **I2. 좌표는 세션 배열 없이는 무의미하다.** 배열(슬롯→문자)은 세션 시드에서만 유도되며 시드는 sealed blob 안에만 있다.
- **I3. 모든 앱 페이로드는 TLS와 별개로 AEAD 암호화된다.** 방향별 키(`k_s2c`, `k_c2s`), 방향별 카운터 nonce, 세션 ID를 AAD에 포함.
- **I4. 세션 키는 매 세션 새로 만든다.** 양쪽 모두 ephemeral X25519. 서버 ephemeral 개인키는 HKDF 직후 소거.
- **I5. 평문(배열·세션 키·복원값)은 호출 동안만, 잠긴 메모리에만 존재한다.** 반환 직후 `sodium_memzero`. 마스터 키 페이지는 사용 시점 외 `sodium_mprotect_noaccess`.
- **I6. C 코어는 무상태다.** 세션 상태는 마스터 파생 키로 봉인한 blob으로 호출자에게 돌려주고, 저장소는 암호문만 보관한다.
- **I7. 클라이언트 비밀은 세션이 소비되면 가치가 없다.** 클라이언트 소거는 최선 노력(`fill(0)`, 비트맵 해제)이며, 진짜 보증은 서버 측 파기에서 나온다.
- **I8. 제어 키(shift, backspace, 모드 전환)는 서버로 보내지 않는다.** 클라이언트가 로컬 상태 기계로 처리하고, 서버에는 최종 값을 구성하는 **문자 탭만** 보낸다(backspace = 마지막 기록 pop). 서버는 편집 습관조차 알지 못한다.

---

## 3. 전체 아키텍처

```
┌──────────────────────┐   HTTPS(+앱 레이어 E2E)   ┌──────────────────────┐        ┌────────────────────────┐
│ 클라이언트 SDK        │ ───────────────────────► │ 통합사 앱 서버        │ ─────► │ skp 서버 SDK            │
│ web / react / ios /  │  1. 세션 생성 요청(kp)     │ (Express/Flask/Spring)│ 호출   │ Java/Python/Node 바인딩 │
│ android              │ ◄─────────────────────── │  - /keypad/session    │ ◄───── │   └ libskp (C 코어)     │
│  - 네이티브 chrome   │  2. {sid, sp, sig, ct}    │  - /keypad/relayout   │        │      ├ crypto(libsodium)│
│  - 타일 블릿         │                           │  - /login (decrypt)   │        │      ├ layout/shuffle   │
│  - 좌표 기록·암호화  │ ───────────────────────► │                       │        │      ├ renderer(stb)    │
│                      │  3. 폼 제출 {sid, ct}     │  세션 저장소(암호문만)│        │      └ wire/sealed blob │
└──────────────────────┘                           └──────────────────────┘        └────────────────────────┘
```

- **서버 SDK는 전송 계층에 무관하다.** 정확한 wire JSON을 만들고/받으므로 통합사는 라우트 2~3개를 그대로 연결하기만 하면 된다.
- **저장소는 바인딩 계층에서 플러그인.** 기본 인메모리(TTL) + 인터페이스(`get/put/take/delete`) + Redis 예제. 저장 내용은 봉인된 암호문뿐.

### 3.1 모노레포 구성

```
secure_keypad/
├─ core/                 # libskp (C11, CMake). crypto · session · wire · layout · renderer
│  ├─ include/skp.h
│  ├─ src/
│  ├─ third_party/       # libsodium(정적), stb_truetype, stb_image_write, cJSON, 폰트(Inter, Roboto)
│  └─ tests/             # 단위 · KAT 벡터 · fuzz · 메모리 잔류 검사
├─ bindings/
│  ├─ node/              # N-API(node-addon-api) + prebuildify → @secure-keypad/server
│  ├─ python/            # cffi + cibuildwheel → secure-keypad-server
│  └─ java/              # JNI + Gradle → dev.securekeypad:skp-server (jar에 네이티브 동봉)
├─ clients/
│  ├─ web/               # TypeScript 코어 → @secure-keypad/web (ESM / CJS / IIFE)
│  ├─ react/             # @secure-keypad/react
│  ├─ ios/               # Swift Package "SecureKeypad" (+ XCFramework 릴리스)
│  └─ android/           # Kotlin AAR dev.securekeypad:secure-keypad-android (+ -compose)
├─ spec/                 # PROTOCOL.md · LAYOUT.md · THREAT-MODEL.md · vectors/*.json
├─ tools/                # skp-keygen CLI · 벡터 생성기 · 레퍼런스 구현(Python)
├─ examples/             # server-node · server-python · server-java · web-vanilla · web-react · ios-demo · android-demo
└─ docs/
```

---

## 4. 프로토콜 설계 (`spec/PROTOCOL.md` 초안)

### 4.1 암호 스위트와 선택 이유

| 프리미티브 | 서버 (C) | Web | iOS | Android |
|---|---|---|---|---|
| 키 교환 X25519 | libsodium | `@noble/curves` | CryptoKit `Curve25519.KeyAgreement` | Tink `X25519` (API 33+는 JCA `XDH` 가능) |
| 서명 Ed25519 (검증) | libsodium | `@noble/curves` | CryptoKit `Curve25519.Signing` | Tink `Ed25519Verify` (33+는 JCA) |
| KDF HKDF-SHA256 | libsodium 1.0.19+ (`crypto_kdf_hkdf_sha256`), 없으면 HMAC으로 직접 | `@noble/hashes` | CryptoKit `HKDF<SHA256>` (iOS 14+) | Tink `Hkdf` 또는 HMAC 직접 |
| AEAD ChaCha20-Poly1305 (IETF, 96-bit nonce) | libsodium | `@noble/ciphers` | CryptoKit `ChaChaPoly` | JCA `ChaCha20/Poly1305` (API 28+) / Tink |
| 세션 봉인(서버 전용) XChaCha20-Poly1305 | libsodium | — | — | — |
| CSPRNG | libsodium `randombytes` | `crypto.getRandomValues` | `SystemRandomNumberGenerator` | `SecureRandom` |
| 메모리 잠금·소거 | `sodium_malloc / mlock / memzero / mprotect` | `fill(0)` 최선 노력 | CryptoKit 키 자동 소거, `memset_s` | `fill(0)` 최선 노력 |

**AES-GCM 대신 ChaCha20-Poly1305인 이유**: libsodium의 AES-GCM은 하드웨어 AES(x86 AES-NI, ARMv8 crypto)가 없는 서버에서 사용 불가라 이식성이 없다. ChaCha20-Poly1305는 서버·iOS·Android 모두 네이티브로 지원하고, 웹은 `@noble/ciphers`(Cure53 감사)로 통일한다. 웹은 AEAD가 어차피 JS이므로 X25519 / HKDF도 `@noble`로 통일해 브라우저 편차를 없앤다.

### 4.2 키 스케줄

```
마스터 키 (32 B, 파일 또는 문자열)
  prk_m     = HKDF-Extract(salt = "skp/v1/master", ikm = master)
  seed_sign = HKDF-Expand(prk_m, "sign", 32)  → Ed25519 키쌍 (crypto_sign_seed_keypair)
  k_state   = HKDF-Expand(prk_m, "state", 32) → sealed session blob 봉인 키
  kid       = SHA-256(pk_sign)[0..4] hex      → 키 회전용 식별자

세션
  sid          = random(16)                                    (base64url)
  (c_sk, c_pk) = X25519 keygen   (클라이언트, ephemeral)
  (s_sk, s_pk) = X25519 keygen   (서버, ephemeral, 세션마다)
  ss           = X25519(s_sk, c_pk)          — all-zero 출력은 거부(low-order point)
  prk          = HKDF-Extract(salt = "skp/v1" || sid, ikm = ss)
  k_s2c        = HKDF-Expand(prk, "s2c" || c_pk || s_pk, 32)   서버→클라이언트
  k_c2s        = HKDF-Expand(prk, "c2s" || c_pk || s_pk, 32)   클라이언트→서버
  s_sk, ss, prk 즉시 소거

메시지
  nonce(dir, ctr) = 0x00000000 || u64be(ctr)   방향별 독립 카운터, 재사용 불가
  aad             = "skp/v1/" || msg_type || sid
  sig             = Ed25519(sk_sign, "skp/v1/session" || kid || sid || c_pk || s_pk || SHA-256(ct))
```

### 4.3 세션 흐름

```
클라이언트                                   통합사 앱 서버                   skp 서버 SDK
   │ 1. POST /keypad/session                       │                                │
   │    {v, kp, type, viewport, opts}              │ createSession(body,{ctx,...})  │
   │ ─────────────────────────────────────────────►│ ──────────────────────────────►│ 시드·배열 생성, 타일 렌더,
   │                                               │◄────────────────────────────── │ AEAD 암호화, 서명
   │ 2. {v, sid, kid, sp, sig, ct}                 │ {response, sealed}             │ sealed = 봉인된 세션 상태
   │◄───────────────────────────────────────────── │ store.put(sid, sealed, ttl)    │
   │ 서명 검증 → X25519 → HKDF → 복호화            │                                │
   │ 네이티브 chrome 그리기 + 타일 블릿            │                                │
   │ 탭 → (layout_id, x, y) 기록 (문자 탭만)       │                                │
   │ (회전·리사이즈 시) POST /keypad/relayout ────►│ relayout(sealed, body) ───────►│ 같은 시드, 새 뷰포트로 재렌더
   │◄──────────────────────────────────────────── │◄────────────────────────────── │ 새 sealed 반환 → store 갱신
   │ 3. 폼 제출 {..., password_enc: {v, sid, ct}}  │ sealed = store.take(sid)       │
   │ ─────────────────────────────────────────────►│ decrypt(sealed, payload, ctx) ►│ 검증 → 히트테스트 → 평문
   │                                               │◄────────────────────────────── │ Secret(잠긴 메모리)
   │                                               │ 사용 후 secret.wipe()          │ 세션 소거(keep 아니면)
```

### 4.4 메시지 포맷

**세션 생성 요청** (평문 JSON, 비밀 없음 — 단, 서명·AAD로 변조 방지)

```json
{ "v": 1, "kp": "<b64 X25519 pub 32B>", "type": "qwerty",
  "viewport": { "w": 390, "dpr": 3, "platform": "ios" },
  "opts": { "maxLen": 32 } }
```

통합사 서버가 덧붙이는 서버 측 옵션(클라이언트가 바꿀 수 없음): `ctx`, `layout`, `blank`, `ttl`, `maxLen` 상한.

**세션 생성 응답**

```json
{ "v": 1, "sid": "<b64url 16B>", "kid": "a1b2c3d4", "sp": "<b64 32B>", "sig": "<b64 64B>", "ct": "<b64>" }
```

`ct`의 평문은 이진 프레이밍(이중 base64 회피): `u32 len | json | u32 len | png(tiles) | u32 len | png(popups)`

```json
{ "w": 1170, "h": 780, "maxLen": 32, "exp": 180,
  "layouts": [
    { "id": 0, "mode": "lower",
      "keys": [ { "r": [9, 24, 96, 126], "role": "char", "t": 0 },
                { "r": [ ... ],           "role": "shift" },
                { "r": [ ... ],           "role": "space" }, ... ] },
    { "id": 1, "mode": "upper", "keys": [ ... ] },
    { "id": 2, "mode": "sym1",  "keys": [ ... ] },
    { "id": 3, "mode": "sym2",  "keys": [ ... ] } ],
  "tile":  { "w": 96, "h": 96, "cols": 10 },
  "popup": { "w": 144, "h": 160, "cols": 10 } }
```

- `role`: `char | space | shift | backspace | mode_abc | mode_sym1 | mode_sym2 | done | blank`
- `t`: 스프라이트 셀 번호 = **공간 순서 번호**. 문자와 무관.
- 타일은 8-bit 알파(회색조 PNG). 클라이언트가 테마 색으로 틴트 → 다크모드 전환에 재렌더 불필요.
- 제어 키 아이콘(⇧ ⌫ 등)은 비밀이 아니므로 클라이언트가 네이티브로 그린다(SF Symbols / Material Icons / 인라인 SVG).

**입력 페이로드** (폼 제출 시 통합사 서버가 그대로 SDK에 전달)

```json
{ "v": 1, "sid": "<b64url>", "ct": "<b64>" }
```

`ct` 평문(고정 길이, 방향 c2s, ctr = 0):

```
u8 ver | u8 rsv | u16 count | record × maxLen (패딩은 0)
record(8 B) = u16 seq | u8 layout_id | u8 flags | u16 x | u16 y      (x, y: 키패드 좌상단 기준 기기 픽셀)
layout_id   = (gen << 3) | mode        gen: relayout 세대, mode: lower=0 upper=1 sym1=2 sym2=3 number=4
```

항상 `maxLen`개로 패딩하므로 암호문 길이가 입력 길이를 드러내지 않는다.

### 4.5 봉인된 세션 상태 (sealed blob)

```
XChaCha20-Poly1305(k_state, nonce = random 24B, aad = "skp/v1/state" || kid)
평문(고정 이진 구조, 약 250 B):
  u8 v | u8 type | u8 policy | u8 gen_count | u16 max_len | u16 flags
  u64 created | u64 expires | sid[16] | ctx_hash[32]
  k_s2c[32] | k_c2s[32] | u64 s2c_ctr
  gens[gen_count] : seed[32] | u16 w_px | u16 dpr_x100 | u8 platform
```

- 배열(슬롯→문자)은 `seed`에서 결정적으로 재생성(`randombytes_buf_deterministic` 기반 DRBG + Fisher-Yates)하므로 blob에 배열 자체를 넣지 않는다. 사각형은 뷰포트에서 재계산한다.
- 세대(`gen`)마다 뷰포트를 기록해 relayout 이전 탭의 좌표도 정확히 복원한다. "재배열" 키(v1.1)는 새 시드의 세대를 추가한다.
- 저장소 없이 blob을 클라이언트에 토큰으로 넘기는 **무상태 모드**도 가능하지만, 1회성 보장을 위해 최소한 "사용된 sid" 집합이 필요하므로 개발·테스트용으로만 문서화한다.

### 4.6 서버 검증 규칙 (decrypt)

1. sealed blob 인증(AEAD) · 만료 확인 · `sid` 일치 · `ctx` 해시 상수시간 비교
2. c2s AEAD 검증(ctr = 0, 배치 모드), 버전 확인
3. `count ≤ maxLen`, 패딩 영역이 전부 0, `seq`가 0..count-1로 연속
4. 각 `layout_id`의 세대·모드 유효, `(x, y)`가 해당 세대 키패드 범위 안
5. 히트테스트(전체 셀 영역, 네이티브처럼 키 사이 간격은 가까운 키에 귀속) → 슬롯 → 문자. 슬롯 역할이 `char` / `space`가 아니면 `SKP_ERR_TAMPERED`
6. UTF-8 결과를 `sodium_malloc` 버퍼로 반환. `keep`이 아니면 blob의 모든 파생 데이터 소거

실패 사유는 열거형 코드(`EXPIRED / BAD_SIG / BAD_MAC / TAMPERED / CTX_MISMATCH / …`)로만 반환하고 값·좌표는 절대 오류 메시지에 포함하지 않는다.

### 4.7 소거 규칙

| 위치 | 대상 | 방법 |
|---|---|---|
| C 코어 | 마스터 키, 파생 키, 세션 키, 시드, 배열, 복원값 | `sodium_malloc`(guard page + mlock + canary), 사용 후 `sodium_free`(memzero). 마스터 키 페이지는 평소 `mprotect_noaccess` |
| C 코어 | 스택·임시 버퍼 | 함수 종료 시 `sodium_memzero`, 컴파일러 최적화 무력화 보장 |
| 바인딩 | 반환된 Secret | Node: `Buffer` + `wipe()` / Python: `bytearray` + `wipe()` + 컨텍스트 매니저 / Java: `char[]`·`byte[]` + `AutoCloseable`(`String` 미사용) |
| 저장소 | sealed blob | decrypt 시 `take`(get + delete). `keep` 옵션 또는 TTL로만 잔존 |
| 로그 | 전부 | 비밀·좌표·배열 출력 금지. 디버그 로그는 sid·길이·오류 코드만 |
| 클라이언트 | 세션 키, 좌표 버퍼, 타일 비트맵 | 제출·닫기·만료 시 `fill(0)`, `ImageBitmap.close()` / `Bitmap.recycle()` / `CGImage` 해제. 백그라운드 전환 시 키패드 가림 |

---

## 5. 키패드 배열과 렌더링 (`spec/LAYOUT.md` 초안)

### 5.1 렌더 방식: "서버는 글리프, 클라이언트는 chrome"

키패드 전체를 한 장의 이미지로 보내는 대신, **비밀인 글자 타일만 서버가 렌더링**하고 키 배경·그림자·라운드·간격·아이콘·팝업 버블은 클라이언트가 네이티브로 그린다.

| 항목 | 전체 이미지 방식 | 타일 + 네이티브 chrome (채택) |
|---|---|---|
| 선명도 | 뷰포트마다 서버가 정확한 픽셀로 렌더 필요, 조금만 어긋나도 흐려짐 | chrome은 벡터, 타일은 1:1 블릿 → 어떤 DPR에서도 선명 |
| 페이로드(QWERTY, 3x) | 4 레이어 × 40~60 KB | 스프라이트 2장 ≈ 20~40 KB |
| 다크모드·테마 | 재렌더 필요 | 알파 타일 틴트, 클라이언트 토큰만 교체 |
| 네이티브 느낌 | 플랫폼 폰트 라이선스 문제(SF 배포 불가) | chrome은 진짜 네이티브, 글리프만 대체 폰트(Inter / Roboto) |
| 보안 성질 | 동일(이미지에 글리프 존재) | 동일. 문자 식별 정보는 여전히 없음 |

`render: "flat"`(전체 이미지 한 장) 모드는 서버가 같은 부품으로 합성만 하면 되므로 v1.x 옵션으로 추가 가능하다.

### 5.2 뷰포트 계약 (찌그러짐 방지의 핵심)

1. 클라이언트가 `viewport = { w: 키패드 컨테이너 논리 폭(pt/dp/css px), dpr, platform }`을 보낸다.
2. 서버가 `W = round(w × dpr)` 기기 픽셀 기준으로 메트릭 테이블(플랫폼별)에서 높이 `H`와 모든 키 사각형을 **기기 픽셀 단위**로 계산하고, 글리프도 그 픽셀 크기로 래스터라이즈한다.
3. 클라이언트는 표면(canvas / UIView / View)을 정확히 `W × H` 기기 픽셀로 만들고(논리 크기 `W/dpr × H/dpr`), 사각형·타일을 **스케일 없이** 그린다.
4. 탭 좌표는 `round((p − origin) × dpr)`로 기기 픽셀 정수로 변환해 보낸다.
5. 폭·DPR·회전이 바뀌면 디바운스(150 ms) 후 `relayout` → 새 세대. 입력 중이던 기록은 이전 세대 좌표로 유지된다.
6. 높이의 진실은 서버(`H`)이며, 클라이언트는 첫 표시(스켈레톤)를 위해 플랫폼별 표준 높이 표를 폴백으로 가진다. 필드가 화면에 나타나면 세션을 **프리페치**해 대부분 스켈레톤 없이 바로 뜨게 한다.
7. Safe area(홈 인디케이터 / 내비게이션 바)는 chrome 바깥 패딩으로 클라이언트가 처리한다.

### 5.3 레이아웃 정의

**QWERTY (4 레이어)** — iOS 형태 기준, Material은 메트릭만 다름

```
lower : q w e r t y u i o p        upper : 동일 + shift 상태
        a s d f g h j k l
   [⇧]  z x c v b n m  [⌫]
   [123]      [space]     [Done]
sym1  : 1 2 3 4 5 6 7 8 9 0        sym2 : [ ] { } # % ^ * + =
        - / : ; ( ) $ & @ "                _ \ | ~ < > € £ ¥ •
  [#+=] . , ? ! '  [⌫]               [123] . , ? ! ' [⌫]
  [ABC]      [space]     [Done]      [ABC]     [space]    [Done]
```

**숫자 패드 (3×4)**

```
 1 2 3
 4 5 6        ← 숫자 10개는 무작위 배치
 7 8 9
[  ] 0 [⌫]    ← 빈 칸 / ⌫ 위치는 옵션
```

숫자 패드는 iOS `numberPad`처럼 Done 키가 없으므로 상단 액세서리 바(Done + 마스킹 미리보기)를 클라이언트가 제공한다.

**메트릭 테이블(초기값, M2에서 실기기 스크린샷과 대조해 보정)**

| 항목 | iOS 스타일 | Material 스타일 |
|---|---|---|
| 총 높이(세로, 폰) | 216 pt (+ safe area) | 실측 후 확정(약 230 dp) |
| 행 간격 / 키 높이 | 54 / 42~43 pt | 실측 |
| 키 모서리 | 5 pt, 1 pt 그림자 | 8 dp, 그림자 없음 |
| 글리프 크기 | 22~23 pt, 팝업 34 pt | 22 sp |
| 숫자 패드 | 3열, 키 46 pt, 간격 7 pt | 실측 |

### 5.4 배열 무작위화 옵션 (추가 요청 반영)

서버 측 옵션이며 클라이언트는 결과만 받는다(클라이언트가 정책을 바꾸거나 알 수 없음).

| 옵션 | 값 | 동작 | 보안 | UX |
|---|---|---|---|---|
| `layout` | `"shuffle"` (**QWERTY 기본**) | 각 행 안에서 문자 무작위 배치. 행 길이·실루엣·제어 키 위치는 네이티브와 동일 | 좌표→문자 추론 불가 | 글자를 찾아야 하지만 키보드 모양은 익숙 |
| | `"full"` | 레이어 전체 문자를 행 구분 없이 무작위 배치 | 최강 | 가장 낯섦 |
| | `"fixed"` | 표준 QWERTY 그대로 | **기하학으로 글자 추론 가능** — 키로거·네트워크 방어만. 로그 경고 출력 | 네이티브와 동일 |
| `blank` (숫자) | `"fixed"` (기본) | 빈 칸 왼쪽 아래, ⌫ 오른쪽 아래, 숫자 10개 무작위 | 좌표 무의미 | 네이티브 숫자 패드와 동일 |
| | `"random"` | 빈 칸 위치까지 무작위(⌫만 고정) | 영역 기반 추정 어려움 | 약간 낯섦 |
| `reshuffleKey` (v1.1) | `true` | 빈 칸에 "재배열" 키 → 새 시드 세대 추가(입력 중 값 유지) | 사용자가 원할 때 재배열 | 국내 금융앱 관행 |
| `reshuffle` (v1.1, 스트리밍 모드) | `"perKey"` | 키 하나 입력마다 배열 변경 | 화면 캡처 + 터치 상관 공격 비용 상승 | 숫자 패드 전용 권장 |
| `antiOcr` (v1.x) | `0..3` | 글리프 폰트·기울기·오프셋 무작위, 미세 노이즈 | 자동 OCR 비용 상승 | 단계 높을수록 네이티브 느낌 감소, 기본 0 |

무작위화는 세션 시드 → DRBG → **편향 없는 Fisher-Yates**(`randombytes_uniform` 동등)로 수행한다.

### 5.5 폰트·글리프·스프라이트

- 래스터라이저: `stb_truetype`(단일 헤더). 폰트: iOS 스타일은 **Inter**(SIL OFL), Material은 **Roboto**(Apache-2.0). SF Pro는 재배포 불가. 통합사가 `fonts` 옵션으로 자체 TTF 지정 가능.
- 글리프 비트맵은 `(폰트, 크기, 코드포인트)` 키로 프로세스 캐시(글자 집합은 공개 정보, 비밀은 배치뿐). 세션 렌더 = 캐시된 비트맵을 무작위 순서로 스프라이트에 복사 → 1~3 ms.
- PNG 인코딩: `stb_image_write` 회색조 8-bit. 타일 스프라이트(키 글리프) + 팝업 스프라이트(iOS 버블용 확대 글리프) 각 1장.

### 5.6 테마 토큰 (클라이언트 전용)

`keypadBg, keyBg, keyBgPressed, keySpecialBg, keySpecialBgPressed, keyText, keyIcon, popupBg, shadow, radius, font` — 플랫폼(`ios | material`) × (`light | dark`) 기본값 제공, 색상 토큰만 통합사 오버라이드 허용. 웹은 UA로 `style` 자동 선택(iOS → ios, 그 외 → material), 강제 지정 가능.

---

## 6. 서버 SDK

### 6.1 C 코어 API (`core/include/skp.h`)

```c
typedef struct skp_ctx skp_ctx;
typedef struct { uint8_t *data; size_t len; } skp_buf;
typedef struct skp_secret skp_secret;

typedef struct {
    const char    *master_key_path;    /* 둘 중 하나 */
    const char    *master_key;         /* base64 / hex 문자열 또는 raw 32 B */
    size_t         master_key_len;
    const char    *font_ios_path;      /* 선택: 기본 내장 Inter 대체 */
    const char    *font_material_path; /* 선택: 기본 내장 Roboto 대체 */
    uint32_t       default_ttl_sec;    /* 0 → 180 */
    uint32_t       max_len_cap;        /* 0 → 256 */
} skp_config;

typedef struct {
    const char *ctx;                   /* 통합사 컨텍스트(로그인 시도 ID 등), NULL 허용 */
    const char *layout;                /* "shuffle" | "full" | "fixed" */
    const char *blank;                 /* "fixed" | "random" */
    uint32_t    ttl_sec, max_len;      /* 0 → 기본값 */
} skp_session_opts;

int  skp_init(skp_ctx **out, const skp_config *cfg);
void skp_free(skp_ctx *ctx);
int  skp_public_key(const skp_ctx *ctx, char *b64_out, size_t cap);      /* 클라이언트에 배포할 Ed25519 검증키 */

int  skp_session_create  (skp_ctx *, const char *req_json, size_t, const skp_session_opts *,
                          skp_buf *resp_json, skp_buf *sealed);
int  skp_session_relayout(skp_ctx *, const skp_buf *sealed, const char *req_json, size_t,
                          skp_buf *resp_json, skp_buf *sealed_out);
int  skp_session_decrypt (skp_ctx *, const skp_buf *sealed, const char *payload_json, size_t,
                          const char *ctx, skp_secret **out);

size_t         skp_secret_len  (const skp_secret *);
const uint8_t *skp_secret_bytes(const skp_secret *);                       /* UTF-8, NUL 미보장 */
void           skp_secret_free (skp_secret *);                             /* sodium_free → 0 채움 */
void           skp_buf_free    (skp_buf *);                                /* 0 채움 후 해제 */

int         skp_keygen(uint8_t out[32]);
const char *skp_strerror(int err);
```

- 컨텍스트는 init 후 불변 → 모든 함수 스레드 안전. 글리프 캐시만 rwlock.
- JSON: cJSON. base64: libsodium `sodium_bin2base64`.
- 테스트 빌드 전용 훅(`skp_test_set_ephemeral / sid / seed`)으로 KAT 벡터 생성.

### 6.2 마스터 키 관리

- `skp-keygen` CLI: `skp-keygen > master.key` (base64 텍스트, 권한 0600 권고) 및 `skp-keygen --pubkey master.key` → 클라이언트 설정용 Ed25519 공개키·`kid` 출력.
- init 입력: `masterKeyPath` | `masterKey`(base64 / hex 문자열, raw 32 B) | 환경변수 `SKP_MASTER_KEY`. 파일 내용은 파싱 직후 소거.
- 회전: 응답의 `kid`로 식별. v1은 단일 키, v1.1에 키 링(여러 키 동시 유지, 새 세션은 최신 키) 추가.
- 마스터 키 유출 시 영향: 서명 위조(가짜 키패드) + 저장소의 sealed blob 복호화(진행 중 세션 배열). 과거 트래픽은 ephemeral ECDH 덕에 안전.

### 6.3 세션 저장소 (바인딩 계층)

```ts
interface SessionStore {
  put(sid: string, sealed: Uint8Array, ttlSec: number): Promise<void>;
  get(sid: string): Promise<Uint8Array | null>;        // relayout 용
  take(sid: string): Promise<Uint8Array | null>;       // decrypt 용: get + delete (원자적)
  delete(sid: string): Promise<void>;
}
```

- 기본: 인메모리 `Map` + TTL 스위퍼(단일 프로세스). 다중 인스턴스는 Redis 어댑터 예제(`GETDEL` 사용).
- 저장소가 보는 것은 봉인된 암호문뿐. 저장소 유출만으로는 배열·키를 알 수 없다(마스터 키 필요).

### 6.4 바인딩

| | Node | Python | Java |
|---|---|---|---|
| 기술 | N-API(`node-addon-api`), `prebuildify` + `node-gyp-build` | `cffi`(out-of-line API 모드) | JNI, jar에 OS/arch별 네이티브 동봉 후 로드 시 추출(`sqlite-jdbc` 방식), `-Dskp.native.path` 오버라이드 |
| 지원 | Node 18+ | 3.9+ | 11+ |
| 배포 | npm `@secure-keypad/server`, prebuilt linux-x64/arm64(glibc·musl) · macOS · win-x64 | PyPI `secure-keypad-server`, `cibuildwheel`(manylinux2014, macOS universal2, win_amd64) | Maven Central `dev.securekeypad:skp-server` |
| Secret | `{ bytes: Buffer, toString(), wipe() }` | `Secret`(`.bytes: bytearray`, `.wipe()`, `with` 지원) | `Secret implements AutoCloseable`(`chars()` / `bytes()`, `close()`가 0 채움) |
| 폴백 | v1.x: WASM 빌드(`@secure-keypad/server-wasm`) — mlock 보장 약함, 문서화 | — | — |

C 코어는 각 바인딩에 **정적 링크**(libsodium 포함)해 런타임 의존성을 없앤다.

### 6.5 통합 예시 (Node / Express)

```ts
import { SecureKeypadServer } from '@secure-keypad/server';

const skp = new SecureKeypadServer({ masterKeyPath: '/etc/skp/master.key' }); // 또는 masterKey: '...'

app.post('/keypad/session', async (req, res) =>
  res.json(await skp.createSession(req.body, { ctx: req.session.id, layout: 'shuffle' })));

app.post('/keypad/relayout', async (req, res) =>
  res.json(await skp.relayout(req.body)));

app.post('/login', async (req, res) => {
  const secret = await skp.decrypt(req.body.password_enc, { ctx: req.session.id });
  try { await verifyPassword(req.body.userId, secret.bytes); }
  finally { secret.wipe(); }                                   // keep 옵션이 없으면 세션은 이미 파기됨
});
```

Python(`with skp.decrypt(payload, ctx=...) as secret:`), Java(`try (Secret s = skp.decrypt(payload, ctx))`)도 같은 형태. 예제는 Express · FastAPI · Spring Boot 세 가지를 제공한다. 세션 생성 엔드포인트는 CPU를 쓰므로 통합사 인증·레이트리밋 뒤에 두도록 문서화한다.

---

## 7. 클라이언트 SDK

### 7.1 공통 동작 (모든 플랫폼이 같은 상태 기계 공유)

- **세션 상태**: `closed → opening(프리페치/요청) → ready → submitting → consumed | error(expired, capture, network)`
- **Shift**: `off → on(1회성) → caps(더블탭)`. `on`에서 문자 입력 시 `off`로 복귀(iOS 동작).
- **모드**: `abc ↔ 123 ↔ #+=`. 모드·shift는 어떤 `layout_id`로 기록할지만 결정한다.
- **버퍼**: 문자 탭 기록 배열(`layout_id, x, y`), `maxLen`까지. backspace = pop(길게 누르면 자동 반복: 500 ms 후 100 ms 간격). `change` 이벤트로 길이만 통지 → 호스트 입력 필드에 `•` 표시.
- **submit()**: 패딩된 배치 생성 → `k_c2s`로 암호화 → 페이로드 문자열 반환 → `consumed`. 서버가 검증에 실패(비밀번호 틀림 등)하면 세션은 이미 파기됐으므로 `reset()`으로 새 세션. React / iOS / Android 래퍼는 이를 자동 처리.
- **보호**: 백그라운드 전환 시 팝업 숨김·키패드 가림, 캡처 감지 시 정책(`warn | close`), 만료 30 s 전 자동 갱신(`relayout`이 아닌 새 세션, 입력 유지 불가 → 만료 전 안내).
- **접근성**: 키 라벨을 접근성 트리에 노출하지 않는다. 키패드 전체를 "보안 키패드" 하나의 요소로 표시. 통합사용 `accessibilityFallback` 훅(스크린리더 사용 중 시스템 키보드 허용 여부) 제공, 기본 없음.

### 7.2 눌림 피드백

| | iOS 스타일 | Material 스타일 | 웹 |
|---|---|---|---|
| 문자 키 | 키 위로 팝업 버블(확대 글리프 타일), 키 본체는 버블 뒤로 숨김 | 키 배경 어두워짐 + (옵션, 기본 켬) 미리보기 팝업 | 터치 기기는 스타일에 따라 동일, 데스크톱은 하이라이트만 |
| 제어 키 | 색 반전(어두운 키 ↔ 밝은 키) | 배경 어두워짐 | 동일 |
| 햅틱 | `UIImpactFeedbackGenerator(.light)`, 옵션 `haptics`(기본 켬) | `performHapticFeedback(KEYBOARD_TAP)` — 시스템 설정 존중 | Android는 `navigator.vibrate(10)`, iOS Safari는 미지원 |
| 소리 | `UIInputViewAudioFeedback` + `UIDevice.playInputClick()` — 키보드 클릭음 설정 존중 | `AudioManager.playSoundEffect(FX_KEYPRESS_STANDARD)` — 터치음 설정 존중 | 기본 끔(WebAudio 옵션) |
| 애니메이션 | 팝업 즉시 표시, 놓을 때 60 ms 페이드 | 하이라이트 즉시, 놓을 때 즉시 복귀 | CSS 트랜지션 |

### 7.3 Web / React (`clients/web`, `clients/react`)

```ts
import { createSecureKeypad } from '@secure-keypad/web';

const kp = createSecureKeypad({
  sessionUrl: '/keypad/session', relayoutUrl: '/keypad/relayout',
  serverPublicKey: 'BASE64_ED25519',        // 생략 시 콘솔 경고, strict: true 면 필수
  type: 'number', maxLen: 6,
  style: 'auto', theme: 'auto',             // ios | material, light | dark
});
kp.attach(document.querySelector('#pin'));  // readonly + inputmode="none", 포커스 시 키패드 열림
kp.on('change', ({ length }) => {});
const payload = await kp.submit();          // '{"v":1,"sid":"…","ct":"…"}' → 폼과 함께 전송
```

```tsx
<SecureKeypadProvider config={{ sessionUrl: '/keypad/session', serverPublicKey }}>
  <SecureKeypadInput type="number" maxLen={6} onSubmit={payload => login(payload)} />
</SecureKeypadProvider>
```

- TypeScript, `tsup` 빌드 → ESM / CJS / IIFE(`<script>` 태그, 전역 `SecureKeypad`). 런타임 의존성은 `@noble/curves`, `@noble/ciphers`, `@noble/hashes`뿐(gzip 약 25 KB). React 패키지는 `react` peer only.
- 렌더: **Shadow DOM** 안의 단일 `<canvas>`(기기 픽셀 `W × H`, CSS 크기 `W/dpr`) + 팝업용 DOM. 호스트 CSS가 키 기하에 영향을 줄 수 없다.
- 모바일웹 체크리스트:
  - `readonly` + `inputmode="none"`으로 시스템 키보드 차단, `pointerdown`/`focus` 가로채서 우리 키패드 열기
  - `position: fixed; bottom: 0` 바텀시트 + `padding-bottom: env(safe-area-inset-bottom)`, `visualViewport` 이벤트로 주소창 변화 대응
  - `touch-action: none`(캔버스) / `manipulation`(컨테이너)로 더블탭 줌·스크롤 차단, `user-select: none`, `-webkit-touch-callout: none`, `-webkit-tap-highlight-color: transparent`
  - 열릴 때 본문 스크롤 잠금, 포커스 필드 `scrollIntoView({ block: 'center' })`
  - `ResizeObserver` + `orientationchange` → 150 ms 디바운스 relayout
  - 문서 요구: `<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">`
  - 이미지는 `createImageBitmap(blob)`로 디코드(CSP 친화, object URL 불필요), 닫을 때 `close()`
- 페이지 이탈(`pagehide`) 시 키·버퍼 소거.

### 7.4 iOS (`clients/ios`, Swift Package `SecureKeypad`)

```swift
let keypad = SecureKeypad(config: .init(sessionURL: url, serverPublicKey: "…", type: .number, maxLen: 6))
keypad.attach(to: pinTextField)             // inputView + inputAccessoryView 설정
let payload = try await keypad.submit()     // String
```

- `SecureKeypadInputView: UIInputView(inputViewStyle: .keyboard)` — 시스템 키보드 배경(블러)을 그대로 얻고, `textField.inputView`로 붙이면 **시스템 키보드와 동일한 슬라이드 애니메이션·`keyboardWillShow` 알림**이 발생해 앱의 기존 키보드 회피 로직이 그대로 동작한다. 높이는 서버 `H / scale`, `allowsSelfSizing = true`.
- 그리기: 키마다 `CALayer`(cornerRadius, shadow), 글리프는 `CGImage` 타일을 틴트해 블릿, 팝업은 iOS 버블 모양 `CAShapeLayer`. 회전·사이즈 클래스 변경 시 relayout.
- 대상 필드: `isSecureTextEntry = true`(서드파티 키보드 차단·텍스트 캐시 방지), 자동 교정 끔, 필드 `text`에는 `•`만 기록.
- 보호: `UIScreen.capturedDidChangeNotification`·`isCaptured`, `userDidTakeScreenshotNotification`, `willResignActive`에서 키패드 가림(앱 전환 스냅샷 대비).
- 암호: CryptoKit만 사용, 서드파티 의존성 0. 전송: `URLSession`(교체 가능한 `Transport` 프로토콜).
- SwiftUI: `SecureKeypadField`(UIViewRepresentable). 배포: SPM(소스) + GitHub Release XCFramework. 최소 iOS 14, Swift 5.9+.

### 7.5 Android (`clients/android`, AAR)

```kotlin
val keypad = SecureKeypad(context, SecureKeypadConfig(sessionUrl, serverPublicKey, type = KeypadType.NUMBER, maxLen = 6))
keypad.attach(editText)                     // showSoftInputOnFocus=false, 하단 패널, FLAG_SECURE
val payload = keypad.submit()               // suspend fun
```

- `SecureKeypadView: View` — `Canvas.drawRoundRect` + 틴트된 `Bitmap` 타일. 패널은 액티비티 DecorView에 하단 정렬로 붙인다(같은 윈도우 → `FLAG_SECURE` 적용이 단순, 인셋 처리 직접). `adjustPan` 옵션으로 포커스 필드가 가려지면 스크롤·이동.
- 대상 필드: `showSoftInputOnFocus = false`, `TYPE_TEXT_VARIATION_PASSWORD | TYPE_TEXT_FLAG_NO_SUGGESTIONS`, 텍스트는 `•`만.
- 보호: 키패드 표시 중 `window.addFlags(FLAG_SECURE)`(닫을 때 복원), `filterTouchesWhenObscured = true`(탭재킹), 키 영역 `importantForAccessibility = NO`, API 35+ `addScreenRecordingCallback` 옵션.
- 암호: **Tink**(X25519 · Ed25519 · HKDF · ChaCha20-Poly1305) 후보, BouncyCastle 대안 — 설치 전 정책대로 검증 후 확정. 전송: `HttpURLConnection` 기본(의존성 0), `Transport` 인터페이스로 OkHttp 교체 가능.
- Compose: 별도 아티팩트 `-compose`(`SecureKeypadField`). 최소 API 24, Kotlin 2.x, Maven Central.

---

## 8. 테스트 · 품질 · CI

| 영역 | 내용 |
|---|---|
| KAT 벡터 (`spec/vectors`) | 고정 마스터 키·ephemeral·sid·seed로 만든 기대값(공개키, 세션 키, 배열, `ct`, 입력 배치 → 평문). C 코어 + 3 바인딩 + 4 클라이언트 **7개 구현 전부** 통과해야 병합 |
| 레퍼런스 구현 | `tools/reference/`에 순수 Python 구현(PyNaCl / cryptography)으로 C 코어를 교차 검증 |
| C 코어 | ctest 단위 테스트, ASan / UBSan / MSan, libFuzzer 하네스(wire 파서 · sealed blob · decrypt), Valgrind |
| 메모리 잔류 검사 | Linux CI에서 create → decrypt → free 후 `/proc/self/maps` 읽기 가능 영역을 스캔해 세션 키·평문·시드 패턴이 없음을 단언(테스트의 기준 사본은 XOR 마스킹) |
| 배열 통계 | 셔플 편향 검사(χ² 테스트, 10만 세션), 시드 재생성 결정성 |
| 클라이언트 시각 회귀 | Playwright 스크린샷(웹, iOS/Android 에뮬레이션), XCTest 스냅샷, Roborazzi. 실기기 시스템 키보드 스크린샷과 픽셀 비교로 메트릭 보정 |
| 통합(E2E) | Node 예제 서버 기동 → Playwright(웹) · XCUITest(시뮬레이터) · Instrumented(에뮬레이터)로 "세션 → 탭 → 제출 → 복호화" 전체 흐름 |
| 정적 분석 | clang-tidy, ESLint / tsc strict, SwiftLint, detekt, `cargo-deny`류 라이선스 검사(폰트·서드파티) |
| CI / 릴리스 | GitHub Actions: 코어 매트릭스 빌드(linux x64/arm64 glibc·musl, macOS universal, win x64) → prebuilt 아티팩트 → 태그 시 npm(provenance) · PyPI(trusted publishing) · Maven Central(GPG) · SPM 태그 + XCFramework 릴리스 |
| 보안 리뷰 | 1.0 전 외부 리뷰 권장. `SECURITY.md`(신고 절차) · `spec/THREAT-MODEL.md` 공개 |

---

## 9. 마일스톤

각 단계는 완료 기준을 만족해야 다음으로 넘어간다. 기간은 우선순위 결정 후 산정.

| 단계 | 산출물 | 완료 기준 |
|---|---|---|
| **M0 명세** | `spec/PROTOCOL.md`, `LAYOUT.md`, `THREAT-MODEL.md`, 벡터 생성기, Python 레퍼런스 구현 | 벡터 파일 생성, 레퍼런스가 자기 벡터를 통과 |
| **M1 C 코어(암호·세션)** | `libskp`: 키 유도, 세션 생성/relayout/decrypt(타일은 자리표시자), sealed blob, `skp-keygen`, 테스트·sanitizer·fuzz | KAT 통과, 메모리 잔류 검사 통과, fuzz 1시간 무크래시 |
| **M2 레이아웃·렌더러** | 메트릭 테이블, 4 레이어 + 숫자 패드, 셔플 정책(`shuffle / full / fixed`, `blank`), stb 글리프·스프라이트·PNG | 실기기 스크린샷 대비 오차 ≤ 1 px, 세션 생성 < 10 ms, QWERTY 3x 페이로드 < 100 KB |
| **M3 Node + Web + React** | `@secure-keypad/server`, `/web`, `/react`, Express 예제, 첫 E2E | 모바일 Safari / Chrome 실기기에서 찌그러짐 없이 동작, Playwright E2E 통과 |
| **M4 Python + Java** | `secure-keypad-server`(wheel), `skp-server`(jar), FastAPI · Spring Boot 예제 | 3 바인딩 KAT 통과, 각 레지스트리 테스트 배포 |
| **M5 iOS** | Swift Package + XCFramework, 데모 앱 | 시스템 키보드와 나란히 놓고 비교 승인, XCUITest E2E |
| **M6 Android** | AAR(+compose), 데모 앱 | Gboard와 비교 승인, Instrumented E2E, FLAG_SECURE 확인 |
| **M7 강화·릴리스** | 보안 문서, 외부 리뷰 반영, 문서 사이트, 1.0.0 릴리스 파이프라인 | 7개 구현 상호 운용 CI 녹색, 릴리스 태그 1회 성공 |
| **v1.1** | 스트리밍 모드, 재배열 키, 키마다 재배열, 키 링 회전, WASM 서버 폴백, flat 렌더 | — |
| **v2** | 한글 2벌식(서버 조합), antiOcr, 무결성 힌트(디버거·오버레이 휴리스틱) | — |

---

## 10. 결정 필요 사항 (기본 가정으로 진행, 답 주시면 반영)

| # | 질문 | 기본 가정 |
|---|---|---|
| D1 | QWERTY 기본 배열 정책? `shuffle`(행 안 무작위)이면 안전하지만 글자를 찾아야 함. `fixed`는 네이티브와 동일하지만 좌표로 글자가 추론됨 | **`shuffle`**, `fixed`는 경고와 함께 옵션 |
| D2 | 렌더 방식: 타일 + 네이티브 chrome vs 전체 이미지 한 장 | **타일 + chrome**, flat은 v1.x 옵션 |
| D3 | 전송 방식: 제출 시 일괄(batch) vs 키마다 전송(stream) | **batch**(v1), stream은 v1.1(키마다 재배열·마지막 글자 표시의 전제) |
| D4 | 한글 입력 범위 | v2 |
| D5 | 최소 지원: iOS 14 / Android API 24 / Node 18 / Python 3.9 / Java 11 / 브라우저 2021+ (Android WebView 90+) | 좌측 값 |
| D6 | 이름·라이선스: `secure-keypad`, npm `@secure-keypad/*`, PyPI `secure-keypad-server`, Maven `dev.securekeypad`, Apache-2.0 | 좌측 값(자리표시자, 조직명 확정 시 교체) |
| D7 | Android 암호 라이브러리: Tink vs BouncyCastle vs API 28+ 한정 후 JCA만 | Tink(검증 후) |
| D8 | 스크린리더 사용자 폴백 정책 | 통합사 훅만 제공, 기본 없음 |

---

## 11. 서드파티 후보 (설치 전 공식 출처·다운로드 수 확인 정책 적용)

| 용도 | 후보 | 라이선스 | 비고 |
|---|---|---|---|
| 암호(C) | libsodium ≥ 1.0.19 | ISC | 정적 링크. HKDF 부재 시 HMAC으로 대체 |
| 글리프 래스터 / PNG | stb_truetype, stb_image_write | MIT / Public Domain | 단일 헤더 |
| JSON(C) | cJSON | MIT | 고정 스키마라 자체 파서로 대체 가능 |
| C 테스트 | ctest + Unity 또는 자체 assert | MIT | |
| 폰트 | Inter, Roboto | SIL OFL 1.1, Apache-2.0 | 재배포 가능. Noto Sans는 v2(한글) |
| Node 바인딩 | node-addon-api, prebuildify, node-gyp-build | MIT | `sodium-native`와 같은 패턴 |
| Python 바인딩 | cffi, cibuildwheel | MIT / BSD | `PyNaCl`과 같은 패턴 |
| Java 빌드 | Gradle(Kotlin DSL), JNI | — | |
| 웹 암호 | @noble/curves, @noble/ciphers, @noble/hashes | MIT | Cure53 감사, 주간 다운로드 수백만 |
| 웹 빌드·테스트 | tsup, vitest, Playwright | MIT / Apache | |
| Android 암호 | Tink (대안 BouncyCastle) | Apache-2.0 / MIT | |
| iOS | 의존성 없음(CryptoKit, URLSession) | — | |

---

## 12. 첫 주 실행 순서 (승인 후)

1. 저장소 초기화(`git init`, 라이선스, CI 스켈레톤, 모노레포 구조)
2. `spec/PROTOCOL.md` 확정판 + Python 레퍼런스 구현 + 벡터 생성
3. `core/` CMake 스켈레톤 + libsodium 서브모듈 + 키 유도·sealed blob 구현 + KAT 테스트
4. 메모리 잔류 검사 하네스 (이후 모든 PR의 게이트)
