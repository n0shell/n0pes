export default {
  async fetch(req, env) {
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    const reply = (obj, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { ...cors, "Content-Type": "application/json" },
      });

    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    if (req.method !== "POST" || req.headers.get("Origin") !== env.ALLOWED_ORIGIN)
      return reply({ ok: false, error: "forbidden" }, 403);

    let body;
    try { body = await req.json(); } catch { return reply({ ok: false, error: "json" }, 400); }

    const dispatch = async (event_type, client_payload) => {
      const r = await fetch(`https://api.github.com/repos/${env.REPO}/dispatches`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.GH_TOKEN}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "inscripciones-worker",
        },
        body: JSON.stringify({ event_type, client_payload }),
      });
      return r.status === 204;
    };

    // Comparación en tiempo constante de la contraseña de admin
    const isAdmin = async (pw) => {
      if (!env.ADMIN_PASSWORD || typeof pw !== "string") return false;
      const enc = new TextEncoder();
      const [a, b] = await Promise.all([
        crypto.subtle.digest("SHA-256", enc.encode(pw)),
        crypto.subtle.digest("SHA-256", enc.encode(env.ADMIN_PASSWORD)),
      ]);
      const x = new Uint8Array(a), y = new Uint8Array(b);
      let diff = 0;
      for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
      return diff === 0;
    };

    const action = body.action || "inscribir";

    // ---- Público: solo inscribirse ----
    if (action === "inscribir") {
      const nombre = String(body.nombre || "").trim();
      const club = String(body.club || "").trim();
      if (nombre.length < 2 || nombre.length > 24 || !club || club.length > 60)
        return reply({ ok: false, error: "datos" }, 400);
      return (await dispatch("inscripcion", { nombre, club }))
        ? reply({ ok: true }) : reply({ ok: false, error: "github" }, 502);
    }

    // ---- Admin: requiere contraseña ----
    if (!(await isAdmin(body.password))) return reply({ ok: false, error: "auth" }, 401);

    if (action === "login") return reply({ ok: true });

    if (action === "borrar") {
      const nombre = String(body.nombre || "").trim();
      if (!nombre || nombre.length > 24) return reply({ ok: false, error: "datos" }, 400);
      return (await dispatch("admin_borrar", { nombre }))
        ? reply({ ok: true }) : reply({ ok: false, error: "github" }, 502);
    }

    if (action === "vaciar") {
      return (await dispatch("admin_vaciar", {}))
        ? reply({ ok: true }) : reply({ ok: false, error: "github" }, 502);
    }

    return reply({ ok: false, error: "accion" }, 400);
  },
};
