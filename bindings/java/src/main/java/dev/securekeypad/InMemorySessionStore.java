package dev.securekeypad;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Single-process session store backed by a {@link ConcurrentHashMap}. Expired entries are dropped on
 * access and swept periodically. Suitable for one server instance; use a shared store (Redis with
 * {@code GETDEL}) behind a load balancer.
 */
public final class InMemorySessionStore implements SessionStore {
    private static final int SWEEP_EVERY = 256;

    private static final class Entry {
        final byte[] sealed;
        final long expiresAtMillis;

        Entry(byte[] sealed, long expiresAtMillis) {
            this.sealed = sealed;
            this.expiresAtMillis = expiresAtMillis;
        }

        boolean expired(long now) {
            return now > expiresAtMillis;
        }
    }

    private final ConcurrentHashMap<String, Entry> map = new ConcurrentHashMap<>();
    private final AtomicInteger ops = new AtomicInteger();

    @Override
    public void put(String sid, byte[] sealed, long ttlSec) {
        if (sid == null || sealed == null) {
            throw new IllegalArgumentException("sid/sealed");
        }
        Entry old = map.put(sid, new Entry(sealed.clone(), System.currentTimeMillis() + ttlSec * 1000L));
        if (old != null) {
            Arrays.fill(old.sealed, (byte) 0);
        }
        maybeSweep();
    }

    @Override
    public byte[] get(String sid) {
        Entry e = map.get(sid);
        if (e == null) {
            return null;
        }
        if (e.expired(System.currentTimeMillis())) {
            if (map.remove(sid, e)) {
                Arrays.fill(e.sealed, (byte) 0);
            }
            return null;
        }
        return e.sealed.clone();
    }

    @Override
    public byte[] take(String sid) {
        Entry e = map.remove(sid);
        if (e == null) {
            return null;
        }
        byte[] out = e.expired(System.currentTimeMillis()) ? null : e.sealed.clone();
        Arrays.fill(e.sealed, (byte) 0);
        return out;
    }

    @Override
    public void delete(String sid) {
        Entry e = map.remove(sid);
        if (e != null) {
            Arrays.fill(e.sealed, (byte) 0);
        }
    }

    /** Number of entries, including not yet swept expired ones. */
    public int size() {
        return map.size();
    }

    private void maybeSweep() {
        if (ops.incrementAndGet() % SWEEP_EVERY != 0) {
            return;
        }
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Entry>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Entry> me = it.next();
            if (me.getValue().expired(now)) {
                if (map.remove(me.getKey(), me.getValue())) {
                    Arrays.fill(me.getValue().sealed, (byte) 0);
                }
            }
        }
    }
}
