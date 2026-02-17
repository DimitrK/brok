## Express rules

### E1 - Use TLS and apply standard security middleware

Express security best practices explicitly recommend TLS and Helmet. ([expressjs.com][7])

**Do**

```ts
app.use(helmet());
app.disable("x-powered-by");
```

**Avoid**

```ts
// no helmet, verbose server fingerprinting left on
```

---

### E2 - Do not trust user input, especially redirects

Express explicitly calls out open redirect risks and shows validating host before `res.redirect`. ([expressjs.com][7])

**Do**

```ts
app.get("/go", (req, res) => {
  const u = new URL(String(req.query.url));
  if (u.host !== "example.com") return res.status(400).end();
  return res.redirect(u.toString());
});
```

**Avoid**

```ts
app.get("/go", (req, res) => res.redirect(String(req.query.url)));
```

---

### E3 - Cookie security and proxy awareness

Express recommends secure cookie options and shows `trust proxy` when behind a proxy. ([expressjs.com][7])

**Do**

```ts
app.set("trust proxy", 1);
app.use(session({
  name: "sessionId",
  secret: process.env.SESSION_SECRET!,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" }
}));
```

**Avoid**

```ts
app.use(session({ secret: "hardcoded", cookie: { secure: false } }));
```

---

### E4 - Own your 404 and error handler behavior

Express suggests custom 404 and error handlers to control information exposure. ([expressjs.com][7])

**Do**

```ts
app.use((req, res) => res.status(404).json({ error: "not_found" }));
app.use((err, req, res, next) => res.status(500).json({ error: "internal_error" }));
```

**Avoid**

```ts
app.use((err, req, res, next) => res.status(500).send(err.stack)); // leaks internals
```

---

## NestJS rules

### N1 - Enforce DTO validation globally with whitelist and forbidUnknown extras

Nest documents using `ValidationPipe`, `whitelist`, and `forbidNonWhitelisted` to strip or reject unexpected properties. ([docs.nestjs.com][8])

**Do**

```ts
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
}));
```

**Avoid**

```ts
app.useGlobalPipes(new ValidationPipe()); // accepts extra properties by default
```

---

### N2 - Avoid request-scoped providers unless truly required

Nest explicitly warns request-scoped providers impact performance and recommends singleton scope unless necessary. ([docs.nestjs.com][9])

**Do**

```ts
@Injectable()
export class PolicyEngine { /* singleton */ }
```

**Avoid**

```ts
@Injectable({ scope: Scope.REQUEST })
export class PolicyEngine { /* becomes per request, can cascade */ }
```

---

## Turborepo rules

### T1 - Task definitions belong in package `package.json`, turbo orchestrates them

Turborepo searches packages for scripts matching task names and runs them in order using `dependsOn` and caches declared outputs. ([Turborepo][10])

**Do**

* each package has `build`, `test`, `lint` scripts
* root `turbo.json` defines orchestration and caching

**Avoid**

* putting real build logic only in root scripts and bypassing turbo’s package graph

---

### T2 - Always declare `outputs` for cacheable tasks

Caching relies on declared outputs. ([Turborepo][10])

**Do**

```json
{
  "tasks": {
    "build": { "outputs": ["dist/**"] }
  }
}
```

**Avoid**

```json
{
  "tasks": {
    "build": { }
  }
}
```

---

### T3 - Use `dependsOn` correctly for graph order

`^build` runs dependency builds first, same-package dependencies omit `^`. ([Turborepo][10])

**Do**

```json
{ "tasks": { "build": { "dependsOn": ["^build"] }, "test": { "dependsOn": ["build"] } } }
```

**Avoid**

* ad hoc ordering in shell scripts

---

### T4 - Keep `dev` non-cacheable and persistent

Turborepo recommends disabling caching for long-running dev tasks and marking them persistent. ([Turborepo][10])

**Do**

```json
{ "tasks": { "dev": { "cache": false, "persistent": true } } }
```

**Avoid**

* caching dev output or treating dev tasks like build artifacts

---

### T5 - Use strict environment handling and include env vars in task hashes

Turborepo requires env vars be declared via `env` and `globalEnv`, and Strict Mode filters runtime env to those accounted for. It also warns not to create or mutate env vars at runtime. ([Turborepo][11])

**Do**

```json
{
  "envMode": "strict",
  "globalEnv": ["NODE_ENV"],
  "tasks": { "build": { "env": ["DATABASE_URL"], "inputs": ["$TURBO_DEFAULT$", ".env*"] } }
}
```

**Avoid**

```json
{ "envMode": "loose" }
```

```json
{ "scripts": { "dev": "export MY_VARIABLE=123 && next dev" } } // turbo cannot hash it reliably
```

---
