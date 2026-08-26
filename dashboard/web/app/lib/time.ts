const SANTIAGO_TIME_ZONE = "America/Santiago";

export function formatSantiagoTimestamp(value: unknown): string {
  if (!value) return "—";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: SANTIAGO_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find(item => item.type === type)?.value || "";
  return `${part("year")}-${part("month")}-${part("day")} ${part("hour")}:${part("minute")}:${part("second")}`;
}

export function formatSantiagoTime(value: unknown): string {
  const formatted = formatSantiagoTimestamp(value);
  return formatted === "—" ? formatted : formatted.slice(11, 16);
}

export function formatSantiagoTimestampWithZone(value: unknown): string {
  const formatted = formatSantiagoTimestamp(value);
  if (formatted === "—") return formatted;
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return formatted;
  const zone = new Intl.DateTimeFormat("en-US", {
    timeZone: SANTIAGO_TIME_ZONE,
    timeZoneName: "shortOffset",
  }).formatToParts(date).find(item => item.type === "timeZoneName")?.value.replace("GMT", "UTC") || "UTC";
  return `${formatted} (${zone})`;
}
