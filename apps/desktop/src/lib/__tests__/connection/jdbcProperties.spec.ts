import { describe, expect, it } from "vitest";
import { buildConnectionUrlCopy, connectionUrlCopyFormats, type ConnectionUrlCopyConfig } from "@/lib/connection/connectionUrlBuilder";
import { parseConnectionUrl } from "@/lib/connection/connectionUrl";
import { parseJdbcProperties } from "@/lib/connection/jdbcProperties";

const base: ConnectionUrlCopyConfig = { db_type: "sqlserver", host: "db.example.com", port: 1433, username: "user", password: "secret", database: "app", ssl: false };
const symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

describe("dialect-specific JDBC credential copying", () => {
  it.each([symbols, " pass;word} ", "%25%40%5E", "中文🔑", "}", "'", " "])("round-trips SQL Server credentials: %j", (password) => {
    const url = buildConnectionUrlCopy({ ...base, username: symbols, password }, "jdbcUrlWithCredentials")!;
    expect(parseConnectionUrl(url)).toMatchObject({ username: symbols, password });
  });

  it("uses Microsoft's brace escaping rather than URI escapes", () => {
    expect(buildConnectionUrlCopy({ ...base, password: 'pass";{}word' }, "jdbcUrlWithCredentials")).toBe('jdbc:sqlserver://db.example.com:1433;databaseName=app;user=user;password={pass";{}}word}');
  });

  it("preserves literal percent escapes from externally supplied SQL Server URLs", () => {
    expect(parseConnectionUrl("jdbc:sqlserver://db.example.com;user=admin;password=%21%25").password).toBe("%21%25");
  });

  it("quotes database names and preserves quoted additional properties", () => {
    const url = buildConnectionUrlCopy({ ...base, database: "db;name}", url_params: "applicationName={a&b;c};encrypt=false", ssl: true }, "jdbcUrlWithCredentials")!;
    expect(parseConnectionUrl(url)).toMatchObject({ database: "db;name}", urlParams: "applicationName={a&b;c};encrypt=false" });
    expect(url).not.toContain("encrypt=true");
  });

  it.each(["password={open", "password={closed}tail", "password=bad{value"])("rejects malformed SQL Server properties: %s", (properties) => {
    expect(() => parseConnectionUrl(`jdbc:sqlserver://db.example.com;${properties}`)).toThrow("Invalid SQL Server JDBC properties");
  });

  it.each([symbols, " pass,word' ", "%25%40%5E", "中文🔑", " "])("quotes Teradata credentials: %j", (password) => {
    const url = buildConnectionUrlCopy({ ...base, db_type: "teradata", username: symbols, password }, "jdbcUrlWithCredentials")!;
    const properties = parseJdbcProperties(url.slice(url.indexOf("/", "jdbc:teradata://".length) + 1), "teradata")!;
    expect(properties.find(({ key }) => key === "user")?.value).toBe(symbols);
    expect(properties.find(({ key }) => key === "password")?.value).toBe(password);
  });

  it("uses Teradata single-quote escaping", () => {
    expect(buildConnectionUrlCopy({ ...base, db_type: "teradata", password: "a,b'c" }, "jdbcUrlWithCredentials")).toBe("jdbc:teradata://db.example.com/DBS_PORT=1433,DATABASE=app,user=user,password='a,b''c'");
  });
  it.each(["'", "'head", "tail'", "''"])("does not offer unsafe Teradata credential URLs: %j", (password) => {
    const config = { ...base, db_type: "teradata" as const, password };
    expect(buildConnectionUrlCopy(config, "jdbcUrlWithCredentials")).toBeNull();
    expect(connectionUrlCopyFormats(config)).not.toContain("jdbcUrlWithCredentials");
    expect(buildConnectionUrlCopy(config, "jdbcUrl")).not.toBeNull();
  });

  it.each(["oracle", "saphana", "exasol", "snowflake"] as const)("preserves existing encoding for unverified %s driver", (db_type) => {
    expect(buildConnectionUrlCopy({ ...base, db_type, password: "a!b'c" }, "jdbcUrlWithCredentials")).toContain("password=a!b'c");
  });
});

describe("JDBC secret redaction", () => {
  it.each([
    ["jdbc:sqlserver://db.example.com;user=user;password={head;tail}}secret};encrypt=true", "jdbc:sqlserver://db.example.com;user=user;password=***;encrypt=true"],
    ["jdbc:teradata://db.example.com/USER=user,PASSWORD='head,tail''secret',CHARSET=UTF8", "jdbc:teradata://db.example.com/USER=user,PASSWORD=***,CHARSET=UTF8"],
    ["jdbc:teradata://db.example.com/PASSWORD=secret", "jdbc:teradata://db.example.com/PASSWORD=***"],
    ["jdbc:sqlserver://db.example.com;password={unclosed;secret", "jdbc:sqlserver://db.example.com;***"],
    ["jdbc:teradata://db.example.com/PASSWORD='unclosed,secret", "jdbc:teradata://db.example.com/***"],
    ["jdbc:sqlserver://db.example.com;password={a;b};PASSWORD=second;accessToken={token;tail}", "jdbc:sqlserver://db.example.com;password=***;PASSWORD=***;accessToken=***"],
  ])("redacts the entire secret in %s", (connection_string, redacted) => {
    const connection = { ...base, db_type: "jdbc" as const, host: "", password: "", connection_string };
    expect(buildConnectionUrlCopy(connection, "jdbcUrl")).toBe(redacted);
    expect(buildConnectionUrlCopy(connection, "url")).toBe(redacted);
    expect(buildConnectionUrlCopy(connection, "jdbcUrlWithCredentials")).toBe(connection_string);
    expect(connectionUrlCopyFormats(connection)).toContain("urlWithPassword");
  });

  it.each([
    { db_type: "sqlserver" as const, url_params: "password={head;tail}" },
    { db_type: "teradata" as const, url_params: "PASSWORD='head,tail'" },
  ])("redacts secrets in additional $db_type properties", ({ db_type, url_params }) => {
    const config = { ...base, db_type, username: "", password: "", url_params };
    expect(buildConnectionUrlCopy(config, "jdbcUrl")).toContain("***");
    expect(buildConnectionUrlCopy(config, "jdbcUrl")).not.toContain("tail");
    expect(connectionUrlCopyFormats(config)).toContain("jdbcUrlWithCredentials");
  });
});
