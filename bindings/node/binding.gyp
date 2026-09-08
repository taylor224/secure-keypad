{
  "variables": {
    "skp_testing%": "0",
    "core_dir": "../../core"
  },
  "targets": [
    {
      "target_name": "skp",
      "sources": [
        "src/skp_node.cc",
        "<(core_dir)/src/skp.c",
        "<(core_dir)/src/skp_crypto.c",
        "<(core_dir)/src/skp_layout.c",
        "<(core_dir)/src/skp_render.c",
        "<(core_dir)/src/skp_state.c",
        "<(core_dir)/src/skp_session.c",
        "<(core_dir)/third_party/cJSON.c",
        "<(SHARED_INTERMEDIATE_DIR)/skp_font_inter.c",
        "<(SHARED_INTERMEDIATE_DIR)/skp_font_roboto.c"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<(core_dir)/include",
        "<(core_dir)/src",
        "<!@(node scripts/sodium-flags.js include)"
      ],
      "libraries": [
        "<!@(node scripts/sodium-flags.js libs)",
        "-lz",
        "-lpthread"
      ],
      "defines": [
        "NAPI_VERSION=8",
        "NODE_ADDON_API_DISABLE_DEPRECATED",
        "SKP_HAVE_ZLIB=1"
      ],
      "cflags_c": ["-std=gnu11", "-fvisibility=hidden"],
      "cflags_cc": ["-std=c++17", "-fvisibility=hidden", "-fexceptions"],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "xcode_settings": {
        "GCC_C_LANGUAGE_STANDARD": "c11",
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "OTHER_CFLAGS": ["-Wno-unused-function"]
      },
      "conditions": [
        ["skp_testing==1", { "defines": ["SKP_TESTING=1"] }]
      ],
      "actions": [
        {
          "action_name": "embed_inter",
          "inputs": ["<(core_dir)/fonts/Inter-Regular.ttf", "scripts/embed.js"],
          "outputs": ["<(SHARED_INTERMEDIATE_DIR)/skp_font_inter.c"],
          "action": ["node", "scripts/embed.js", "<(core_dir)/fonts/Inter-Regular.ttf", "<(SHARED_INTERMEDIATE_DIR)/skp_font_inter.c", "skp_font_inter"]
        },
        {
          "action_name": "embed_roboto",
          "inputs": ["<(core_dir)/fonts/Roboto-Regular.ttf", "scripts/embed.js"],
          "outputs": ["<(SHARED_INTERMEDIATE_DIR)/skp_font_roboto.c"],
          "action": ["node", "scripts/embed.js", "<(core_dir)/fonts/Roboto-Regular.ttf", "<(SHARED_INTERMEDIATE_DIR)/skp_font_roboto.c", "skp_font_roboto"]
        }
      ]
    }
  ]
}
