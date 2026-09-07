# secure-keypad server SDK for Java

`dev.securekeypad:skp-server` wraps the C core (`core/`) through a small JNI shim. The jar bundles the
native library (`libskp` + libsodium + zlib, statically linked) for the platform it was built on under
`native/<os>-<arch>/`.

Requirements: Java 11+ at runtime (tests need 17+), a JDK, CMake ≥ 3.20, a C compiler, libsodium and
zlib development files (`brew install libsodium`, `apt install libsodium-dev zlib1g-dev`).

## Build and test

```sh
cd bindings/java
./gradlew build test          # builds core + JNI via CMake, runs JUnit 5
./gradlew publishToMavenLocal # optional
```

`CMAKE=/path/to/cmake ./gradlew build` overrides CMake discovery. The native build lands in
`build/native`, the bundled copy in `build/native-res/native/<os>-<arch>/`.

## Usage

```java
import dev.securekeypad.*;

SecureKeypadServer skp = SecureKeypadServer.builder()
        .masterKeyPath(Paths.get("/etc/skp/master.key"))   // or .masterKey("hex or base64") / .masterKey(byte[32])
        .build();

// POST /keypad/session  → body is the client's request JSON, response is what you return verbatim
String response = skp.createSession(requestBody, SessionOptions.builder()
        .ctx(loginAttemptId)      // must be presented again at decrypt
        .layout("shuffle")        // "shuffle" (default) | "full" | "fixed"
        .build());

// POST /keypad/relayout → same shape
String relayout = skp.relayout(requestBody);

// POST /login → the form carries the payload {v, sid, ct} produced by the client SDK
try (Secret secret = skp.decrypt(payloadJson, loginAttemptId)) {
    char[] password = secret.chars();
    try {
        verify(userId, password);
    } finally {
        Arrays.fill(password, '\0');
    }
}
```

`SecureKeypadServer.keygen()` returns a fresh base64 master key; `publicKey()` and `keyId()` give the
values clients pin. The instance is thread safe; create one per process and `close()` it at shutdown.

## Sessions and the store

Sealed session blobs (opaque ciphertext) are kept in a `SessionStore` between `createSession` and
`decrypt`. The default `InMemorySessionStore` is per process; behind a load balancer supply your own
implementation (Redis with `GETDEL` for `take`). `decrypt(payload, ctx)` removes the blob *before*
opening it, so a session is consumed by its first attempt, successful or not. Pass `keep = true` only when
you deliberately want a session to be decryptable more than once.

## Wiping

The JVM cannot lock or reliably wipe memory, so the SDK keeps the value out of `String`s:

- `Secret.bytes()` returns the UTF-8 array owned by the secret; `Secret.close()` (try-with-resources)
  zeroes it.
- `Secret.chars()` returns a fresh `char[]` that you must `Arrays.fill` yourself.
- Never build a `String` from the value: strings are immutable, may be interned, and survive until
  garbage collection copies them somewhere else.

Inside the native layer every secret lives in `sodium_malloc` memory and is zeroed before the call returns
(see `core/tests/test_residue.c`). Master key text passed to the builder is zeroed after use.

## Errors

Every failure is a `SkpException` with `kind()` (`EXPIRED`, `BAD_MAC`, `TAMPERED`, `CTX_MISMATCH`,
`SID_MISMATCH`, `BAD_REQUEST`, `UNSUPPORTED`, `BAD_KEY`, `IO`, `CRYPTO`, `SESSION_NOT_FOUND`, …) and
`code()`. Messages never include values or coordinates. Map them to generic client errors; do not
distinguish them in user-facing responses beyond "try again".

## Native library loading

`NativeLoader` extracts `native/<os>-<arch>/libskp_jni.(dylib|so)` from the jar into a temporary
directory (deleted on exit) and `System.load`s it. Override with
`-Dskp.native.path=/path/to/libskp_jni.dylib`. Building jars that bundle several platforms is a release
pipeline concern: build on each platform and merge the `native/` directories.
