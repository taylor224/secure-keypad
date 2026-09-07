# secure-keypad

Open-source secure keypad: the server renders per-session shuffled keypads, the client shows a native-looking
keyboard and sends back only encrypted tap coordinates, and the server SDK turns them into the typed value.
The client never knows what was typed; nothing secret survives the session.

Design plan: [docs/PLAN.md](docs/PLAN.md) (Korean). Specification: [spec/PROTOCOL.md](spec/PROTOCOL.md),
[spec/LAYOUT.md](spec/LAYOUT.md), [spec/THREAT-MODEL.md](spec/THREAT-MODEL.md).

| Component | Path | Status |
|---|---|---|
| C core (`libskp`) | `core/` | in progress |
| Server bindings | `bindings/node`, `bindings/python`, `bindings/java` | planned |
| Web / React clients | `clients/web`, `clients/react` | planned |
| iOS client | `clients/ios` | planned |
| Android client | `clients/android` | planned |
| Reference implementation and vectors | `tools/reference`, `spec/vectors` | in progress |

License: Apache-2.0. Bundled fonts: Inter (SIL OFL 1.1), Roboto (Apache-2.0). Bundled code: libsodium (ISC),
stb (MIT / public domain), cJSON (MIT).
