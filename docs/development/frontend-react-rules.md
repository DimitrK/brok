
## React rules

### R1 - Hooks must be called unconditionally at top level

React relies on call order, so no hooks in loops, conditions, or nested functions. ([react.dev][1])

**Do**

```tsx
function Panel({ enabled }: { enabled: boolean }) {
  const [open, setOpen] = useState(false);
  if (!enabled) return null;
  return <button onClick={() => setOpen(x => !x)}>{String(open)}</button>;
}
```

**Avoid**

```tsx
function Panel({ enabled }: { enabled: boolean }) {
  if (enabled) {
    const [open, setOpen] = useState(false); // invalid
    return <button onClick={() => setOpen(!open)} />;
  }
  return null;
}
```

---

### R2 - Avoid Effects for derived state

If you are only reacting to props or state changes without an external system, don’t use an Effect. Calculate during render. ([react.dev][2])

**Do**

```tsx
const fullName = `${user.first} ${user.last}`;
return <div>{fullName}</div>;
```

**Avoid**

```tsx
const [fullName, setFullName] = useState("");
useEffect(() => setFullName(`${user.first} ${user.last}`), [user]);
```

---

### R3 - Treat `exhaustive-deps` as correctness, not style

Missing dependencies can cause stale closures and incorrect behavior. ([react.dev][3])

**Do**

```tsx
useEffect(() => {
  trackEvent(userId);
}, [userId]);
```

**Avoid**

```tsx
useEffect(() => {
  trackEvent(userId);
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, []);
```

---

### R4 - Fix Effects that rerun too often by removing unstable deps

React docs explicitly warn that object and function dependencies can cause excessive reruns and recommend extracting non-reactive logic. ([react.dev][4])

**Do**

```tsx
const stableQuery = useMemo(() => ({ q, limit: 20 }), [q]);

useEffect(() => {
  fetchResults(stableQuery);
}, [stableQuery]);
```

**Avoid**

```tsx
useEffect(() => {
  fetchResults({ q, limit: 20 }); // new object every render
}, [{ q, limit: 20 }]);
```

---

### R5 - Use keys intentionally to control state preservation and reset

React preserves state by position in the tree and keys influence that behavior. ([react.dev][5])

**Do**

```tsx
return <Editor key={docId} docId={docId} />;
```

**Avoid**

```tsx
return <Editor docId={docId} />; // state may incorrectly persist across doc changes
```

---

### R6 - Never render untrusted HTML

`dangerouslySetInnerHTML` can introduce XSS if content is not trusted. ([react.dev][6])

**Do**

```tsx
return <pre>{message}</pre>;
```

**Avoid**

```tsx
return <div dangerouslySetInnerHTML={{ __html: userSuppliedHtml }} />;
```

---
