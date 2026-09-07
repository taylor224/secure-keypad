package dev.securekeypad;

/**
 * Holds sealed session blobs between {@code createSession} and {@code decrypt}. Blobs are opaque
 * ciphertext (only the core library initialised with the same master key can open them), so a store may
 * live anywhere: memory, Redis, a database. Implementations must be thread safe.
 *
 * <p>{@link #take} is the single-use primitive: it must return the blob and remove it atomically so that
 * two concurrent decrypt calls cannot both succeed.
 */
public interface SessionStore {
    /** Stores {@code sealed} under {@code sid}; the entry expires after {@code ttlSec} seconds. */
    void put(String sid, byte[] sealed, long ttlSec);

    /** Returns a copy of the blob, or {@code null} when absent or expired. */
    byte[] get(String sid);

    /** Returns the blob and removes it atomically, or {@code null} when absent or expired. */
    byte[] take(String sid);

    /** Removes the blob if present. */
    void delete(String sid);
}
