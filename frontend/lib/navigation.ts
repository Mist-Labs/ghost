export function sanitizeNextPath(
  value: unknown,
  fallback = "/account",
): string {
  if (typeof value !== "string") {
    return fallback;
  }

  const trimmed = value.trim();
  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) {
    return fallback;
  }

  if (trimmed.includes("\\") || /[\r\n]/.test(trimmed)) {
    return fallback;
  }

  return trimmed;
}
