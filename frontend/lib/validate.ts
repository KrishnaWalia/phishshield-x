export const MAX_MESSAGE_LENGTH = 5000;

export type Validation<T> = { ok: true; value: T } | { ok: false; error: string };

/** Accepts "example.com" (assumes https) or a full http(s) URL. */
export function validateUrlInput(raw: string): Validation<string> {
  const input = raw.trim();
  if (!input) return { ok: false, error: "Enter a URL to scan." };
  if (input.length > 2048) return { ok: false, error: "That URL is too long (2,048 characters max)." };
  if (/\s/.test(input)) return { ok: false, error: "A URL cannot contain spaces." };

  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  try {
    const u = new URL(candidate);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return { ok: false, error: "Only http:// and https:// URLs can be scanned." };
    }
    if (!u.hostname.includes(".")) {
      return { ok: false, error: "That doesn't look like a full web address, e.g. https://example.com." };
    }
    return { ok: true, value: candidate };
  } catch {
    return { ok: false, error: "That isn't a valid URL. Try something like https://example.com/login." };
  }
}

export function validateMessageInput(raw: string): Validation<string> {
  const text = raw.trim();
  if (!text) return { ok: false, error: "Paste the message you want to check." };
  if (text.length > MAX_MESSAGE_LENGTH) {
    return { ok: false, error: `Messages are limited to ${MAX_MESSAGE_LENGTH.toLocaleString()} characters.` };
  }
  return { ok: true, value: text };
}
