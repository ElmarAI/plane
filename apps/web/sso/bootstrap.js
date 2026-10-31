/* SPDX-License-Identifier: AGPL-3.0-only
 * Native OIDC entry for the pinned CE frontend. Authentication remains server-side.
 */
(() => {
  const initial = new URL(window.location.href);
  const localLogin = initial.pathname === "/" && initial.searchParams.get("local_login") === "1";
  let checking = false;
  let redirecting = false;

  function target(url) {
    const next = url.searchParams.get("next_path") || url.pathname + url.search + url.hash;
    // Only same-origin paths; callback independently validates the return target.
    return next.startsWith("/") && !next.startsWith("//") && !next.includes("\\") ? next : "/";
  }

  async function check(url) {
    if (localLogin || checking || redirecting || /^\/(auth|api|god-mode|spaces)(\/|$)/.test(url.pathname)) return;
    checking = true;
    const next = target(url);
    try {
      const response = await window.fetch("/api/users/me/", {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (response.status === 401 || response.status === 403) {
        redirecting = true;
        window.location.replace("/auth/oidc/?" + new URLSearchParams({ next_path: next }));
      }
    } catch {
      // A network failure is not proof of an expired session. Do not start a login loop.
    } finally {
      checking = false;
    }
  }

  // Detect the SPA's return to its password page after session expiry as well.
  for (const method of ["pushState", "replaceState"]) {
    const original = window.history[method];
    window.history[method] = function (...args) {
      const result = original.apply(this, args);
      const url = new URL(window.location.href);
      if (url.pathname === "/") void check(url);
      return result;
    };
  }
  window.addEventListener("popstate", () => {
    const url = new URL(window.location.href);
    if (url.pathname === "/") void check(url);
  });
  void check(initial);
})();
