# node-payments-api — intentionally vulnerable demo target

**Do not deploy this.** It exists only as a real remediation target for the
Mphasis Synapse CTEM live-remediation loop (`backend/app/remediation/`).

- It pins `lodash@4.17.4`, which carries **CVE-2019-10744** (prototype pollution
  via `_.merge` / `_.defaultsDeep`), among other advisories fixed by `4.17.21`.
- `src/server.js` exposes `POST /merge`, which deep-merges caller JSON into a base
  config using `_.merge` — the real runtime-reachable sink for that CVE.
- `test/app.test.js` is a functional contract suite (`node --test`) that passes on
  both `4.17.4` and `4.17.21`, providing "no regression" evidence for the bump.

The CTEM live adapter snapshots this directory into a scratch git workspace, scans
it, bumps `lodash` to the fixed version, runs the tests, re-scans to prove the CVE
is gone, and (in PR mode) opens a real GitHub pull request. `node_modules/` is not
committed — the adapter runs `npm install` in its workspace.
