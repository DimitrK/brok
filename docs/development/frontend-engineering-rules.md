
# Frontend rules (React admin UI)

## F1. Keep UI state local; prefer derived state

**Why**: avoids bugs and stale flags.

**Do**

```tsx
const isHighRisk = approval.summary.risk_tier === "high";
```

**Avoid**

```tsx
const [isHighRisk, setIsHighRisk] = useState(false); // can desync
```

---

## F2. No “boolean UI trap” props; use explicit variants

**Why**: components become unreadable.

**Do**

```tsx
<Button intent="danger" />
```

**Avoid**

```tsx
<Button red />
```

---

## F3. Async safety: cancel stale requests

**Why**: prevents race conditions and wrong UI updates.

**Do**

```tsx
useEffect(() => {
  const ac = new AbortController();
  fetch(url, { signal: ac.signal }).catch(() => {});
  return () => ac.abort();
}, [url]);
```

**Avoid**

```tsx
useEffect(() => { fetch(url).then(setState); }, [url]);
```

---

## F4. Treat server data as untrusted and validate at the boundary

**Why**: defense-in-depth, reduces runtime crashes.

**Do**

* validate with schema (zod or JSON-schema runtime validator) when ingesting API responses

**Avoid**

* assume `any` payload shape

---

## F5. Avoid overfetching and chatty polling

**Why**: audit and approvals can grow large.

**Do**

* cursor-based pagination for audit events
* fetch-on-demand for large payload views

**Avoid**

* “load everything” audit table

---

## F6. Accessibility and keyboard navigation by default

**Why**: internal tools still benefit, and it forces cleaner UI structure.

**Do**

* semantic buttons/inputs
* focus management on modals
* visible focus styles

**Avoid**

* clickable divs for actions

---

## F7. Never render raw HTML from upstream without sanitization

**Why**: XSS in admin UI is catastrophic.

**Do**

* render text, not HTML
* sanitize if you must render rich content

**Avoid**

```tsx
<div dangerouslySetInnerHTML={{ __html: response }} />
```

---

## F8. Component boundaries reflect domains

**Why**: prevents “God components.”

**Do**

* `ApprovalList`, `ApprovalDetail`, `PolicyEditor`, `AuditSearch`

**Avoid**

* single `AdminPage.tsx` with everything

---

## F9. No business logic in components; use pure “selectors”

**Why**: testable and reusable.

**Do**

```ts
const selectPending = (items: Approval[]) => items.filter(x => x.status === "pending");
```

**Avoid**

```tsx
{approvals.filter(...).map(...)} // repeated logic across components
```

---

## F10. Keep network layer centralized and typed

**Why**: consistent error handling and auth.

**Do**

* one `apiClient` wrapper with:

  * retries (only for safe GET)
  * abort support
  * standardized error shape

**Avoid**

* `fetch` scattered across components

---

## F11. Never cache secrets or tokens in localStorage by default

**Why**: XSS turns into account takeover.

**Do**

* memory-only tokens or httpOnly cookies (depending on your admin auth model)

**Avoid**

* storing admin tokens in localStorage

---

## F12. Paginate and stream long lists

**Why**: audit logs grow.

**Do**

* cursor pagination
* virtualized lists if necessary

**Avoid**

* render 50k audit rows in DOM

---

## F13. UI for approvals should be “diff-first”

**Why**: reviewer decision quality.

**Do**

* show canonical descriptor and what rule will be created
* show constraints and risk tier

**Avoid**

* approve button with no context

---
