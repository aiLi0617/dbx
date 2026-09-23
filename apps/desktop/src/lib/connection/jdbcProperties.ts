/** Property grammars used by Microsoft JDBC 8.4+ and Teradata JDBC. */
export type JdbcPropertyStyle = "sqlserver" | "teradata";

export interface JdbcProperty {
  key: string;
  value: string;
  raw: string;
}

export function quoteJdbcProperty(value: string, style: JdbcPropertyStyle): string {
  if (/^[\w.~%-]+$/.test(value)) return value;
  return style === "sqlserver" ? `{${value.replace(/}/g, "}}")}}` : `'${value.replace(/'/g, "''")}'`;
}

/** No percent decoding: percent escapes are literal in these property grammars. */
export function parseJdbcProperties(source: string, style: JdbcPropertyStyle, separators = style === "sqlserver" ? ";" : ","): JdbcProperty[] | null {
  const opening = style === "sqlserver" ? "{" : "'";
  const closing = style === "sqlserver" ? "}" : "'";
  const properties: JdbcProperty[] = [];
  let index = 0;
  while (index < source.length) {
    while (index < source.length && (separators.includes(source[index]) || /\s/.test(source[index]))) index++;
    if (index === source.length) break;
    const start = index;
    while (index < source.length && source[index] !== "=" && !separators.includes(source[index])) index++;
    if (source[index] !== "=") return null;
    const key = source.slice(start, index).trim();
    if (!key) return null;
    index++;
    while (index < source.length && /\s/.test(source[index])) index++;
    let value = "";
    if (source[index] === opening) {
      index++;
      let closed = false;
      while (index < source.length) {
        const character = source[index++];
        if (character !== closing) {
          value += character;
        } else if (source[index] === closing) {
          value += closing;
          index++;
        } else {
          closed = true;
          break;
        }
      }
      if (!closed) return null;
      while (index < source.length && /\s/.test(source[index])) index++;
      if (index < source.length && !separators.includes(source[index])) return null;
    } else {
      const valueStart = index;
      while (index < source.length && !separators.includes(source[index])) index++;
      value = source.slice(valueStart, index).trim();
      if (style === "sqlserver" && value.includes("{")) return null;
    }
    properties.push({ key, value, raw: source.slice(start, index) });
    if (index < source.length) index++;
  }
  return properties;
}

export function redactJdbcProperties(source: string, style: JdbcPropertyStyle): string {
  const properties = parseJdbcProperties(source, style);
  // An invalid quoted value has no trustworthy boundary. Never copy its tail.
  if (!properties) return "***";
  const secret = /^(?:password|pwd|pass|token|secret|key|accessToken|logdata|new_password|ssltruststore_password)$/i;
  if (!properties.some(({ key }) => secret.test(key))) return source;
  return properties.map(({ key, raw }) => (secret.test(key) ? `${key}=***` : raw)).join(style === "sqlserver" ? ";" : ",");
}

/** DBX also accepts &/; separated form parameters; never split inside quoted values. */
export function normalizeJdbcProperties(source: string, style: JdbcPropertyStyle): JdbcProperty[] | null {
  return parseJdbcProperties(source.trim().replace(/^[?&;,]+/, ""), style, style === "sqlserver" ? ";&" : ",;&");
}
