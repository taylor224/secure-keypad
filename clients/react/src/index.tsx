import { createSecureKeypad, type SecureKeypad, type SecureKeypadConfig } from "@secure-keypad/web";
import React, { createContext, forwardRef, useCallback, useContext, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";

export type { SecureKeypad, SecureKeypadConfig } from "@secure-keypad/web";

type SharedConfig = Partial<Omit<SecureKeypadConfig, "type">>;

const ConfigContext = createContext<SharedConfig>({});

/** Shares endpoint / key / style configuration with every keypad below it. */
export function SecureKeypadProvider({ config, children }: { config: SharedConfig; children: React.ReactNode }) {
  return <ConfigContext.Provider value={config}>{children}</ConfigContext.Provider>;
}

export interface UseSecureKeypadOptions extends Partial<SecureKeypadConfig> {
  type: SecureKeypadConfig["type"];
}

export interface SecureKeypadHandle {
  keypad: SecureKeypad | null;
  length: number;
  ready: boolean;
  /** Returns the encrypted payload and consumes the session. */
  submit: () => string;
  reset: () => Promise<void>;
  open: () => Promise<void>;
  close: () => void;
}

/** Creates a keypad instance bound to the input you attach through the returned ref. */
export function useSecureKeypad(options: UseSecureKeypadOptions): SecureKeypadHandle & { inputRef: React.RefCallback<HTMLInputElement> } {
  const shared = useContext(ConfigContext);
  const config = useMemo<SecureKeypadConfig>(() => ({ ...shared, ...options } as SecureKeypadConfig), [shared, options]);
  const keypadRef = useRef<SecureKeypad | null>(null);
  const inputEl = useRef<HTMLInputElement | null>(null);
  const [length, setLength] = useState(0);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (typeof document === "undefined") return;
    const kp = createSecureKeypad(config);
    keypadRef.current = kp;
    const offs = [
      kp.on("change", ({ length }) => setLength(length)),
      kp.on("ready", () => setReady(true)),
      kp.on("submit", () => {
        setLength(0);
        setReady(false);
      }),
      kp.on("expire", () => setReady(false)),
    ];
    if (inputEl.current) kp.attach(inputEl.current);
    return () => {
      offs.forEach((off) => off());
      kp.destroy();
      keypadRef.current = null;
    };
  }, [config]);

  const inputRef = useCallback<React.RefCallback<HTMLInputElement>>((el) => {
    inputEl.current = el;
    if (el && keypadRef.current) keypadRef.current.attach(el);
  }, []);

  return {
    inputRef,
    keypad: keypadRef.current,
    length,
    ready,
    submit: () => {
      if (!keypadRef.current) throw new Error("keypad not mounted");
      return keypadRef.current.submit();
    },
    reset: () => keypadRef.current?.reset() ?? Promise.resolve(),
    open: () => keypadRef.current?.open() ?? Promise.resolve(),
    close: () => keypadRef.current?.close(),
  };
}

export interface SecureKeypadInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type" | "onSubmit" | "onChange" | "value"> {
  type: SecureKeypadConfig["type"];
  maxLen?: number;
  /** Name of a hidden input that receives the payload on form submit. */
  payloadName?: string;
  onChange?: (length: number) => void;
  /** Called when the user presses Done. Receives the encrypted payload; the session is consumed. */
  onSubmit?: (payload: string) => void;
  keypad?: Partial<SecureKeypadConfig>;
}

/** A password-style input driven by the secure keypad. The DOM input only ever shows dots. */
export const SecureKeypadInput = forwardRef<SecureKeypadHandle, SecureKeypadInputProps>(function SecureKeypadInput(
  { type, maxLen, payloadName, onChange, onSubmit, keypad, ...inputProps },
  ref,
) {
  const shared = useContext(ConfigContext);
  const options = useMemo<UseSecureKeypadOptions>(
    () => ({ ...shared, ...(keypad ?? {}), type, maxLen, hiddenInputName: payloadName }),
    [shared, keypad, type, maxLen, payloadName],
  );
  const handle = useSecureKeypad(options);
  useImperativeHandle(ref, () => handle, [handle]);
  useEffect(() => {
    onChange?.(handle.length);
  }, [handle.length, onChange]);
  useEffect(() => {
    const kp = handle.keypad;
    if (!kp || !onSubmit) return;
    return kp.on("done", () => {
      try {
        onSubmit(kp.submit());
      } catch {
        /* no session yet */
      }
    });
  }, [handle.keypad, onSubmit]);
  return <input ref={handle.inputRef} type="password" readOnly inputMode="none" autoComplete="off" {...inputProps} />;
});
