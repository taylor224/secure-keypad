package dev.securekeypad;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * Loads the bundled {@code skp_jni} native library. Resolution order:
 * <ol>
 *   <li>{@code -Dskp.native.path=/path/to/libskp_jni.(dylib|so|dll)}</li>
 *   <li>the classpath resource {@code native/<os>-<arch>/<library>} extracted to a temporary
 *       directory that is deleted on exit</li>
 * </ol>
 */
final class NativeLoader {
    private static boolean loaded;

    private NativeLoader() {
    }

    static synchronized void load() {
        if (loaded) {
            return;
        }
        String override = System.getProperty("skp.native.path");
        if (override != null && !override.isEmpty()) {
            System.load(new File(override).getAbsolutePath());
            loaded = true;
            return;
        }
        String resource = "native/" + platform() + "/" + libraryFileName();
        try (InputStream in = NativeLoader.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new UnsatisfiedLinkError("secure-keypad: no bundled native library for " + platform()
                        + " (missing classpath resource " + resource + "); build it or set -Dskp.native.path");
            }
            Path dir = Files.createTempDirectory("skp-native");
            Path file = dir.resolve(libraryFileName());
            Files.copy(in, file, StandardCopyOption.REPLACE_EXISTING);
            file.toFile().deleteOnExit();
            dir.toFile().deleteOnExit();
            System.load(file.toAbsolutePath().toString());
        } catch (IOException e) {
            UnsatisfiedLinkError err = new UnsatisfiedLinkError("secure-keypad: cannot extract native library: " + e);
            err.initCause(e);
            throw err;
        }
        loaded = true;
    }

    static String platform() {
        return osName() + "-" + archName();
    }

    static String osName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("mac") || os.contains("darwin")) {
            return "darwin";
        }
        if (os.contains("win")) {
            return "windows";
        }
        return "linux";
    }

    static String archName() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("aarch64") || arch.equals("arm64")) {
            return "aarch64";
        }
        if (arch.equals("amd64") || arch.equals("x86_64") || arch.equals("x64")) {
            return "x86_64";
        }
        return arch;
    }

    static String libraryFileName() {
        switch (osName()) {
            case "darwin":
                return "libskp_jni.dylib";
            case "windows":
                return "skp_jni.dll";
            default:
                return "libskp_jni.so";
        }
    }
}
