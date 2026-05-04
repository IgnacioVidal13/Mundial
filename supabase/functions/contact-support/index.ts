const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY");
const CONTACT_TO = Deno.env.get("CONTACT_TO") || "contactosoportelista@gmail.com";
const CONTACT_FROM = Deno.env.get("CONTACT_FROM") || "Mi Lista Mundialista <onboarding@resend.dev>";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ ok: false, error: "method_not_allowed" }, 405);
  }

  if (!RESEND_API_KEY) {
    return jsonResponse({ ok: false, error: "missing_resend_key" }, 500);
  }

  let payload: { email?: string; mensaje?: string; usuario?: string; nombre?: string } = {};
  try {
    payload = await req.json();
  } catch {
    return jsonResponse({ ok: false, error: "invalid_json" }, 400);
  }

  const email = String(payload.email || "").trim();
  const mensaje = String(payload.mensaje || "").trim();
  const usuario = String(payload.usuario || "").trim();
  const nombre = String(payload.nombre || "").trim();

  if (!email || !email.includes("@")) {
    return jsonResponse({ ok: false, error: "invalid_email" }, 400);
  }

  if (!mensaje) {
    return jsonResponse({ ok: false, error: "empty_message" }, 400);
  }

  const subject = `Contacto desde Mi Lista Mundialista`;
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5">
      <h2>Nuevo mensaje de contacto</h2>
      <p><strong>De:</strong> ${email}</p>
      <p><strong>Usuario:</strong> ${nombre || "sin nombre"} ${usuario ? `(${usuario})` : ""}</p>
      <p><strong>Mensaje:</strong></p>
      <pre style="white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:8px">${mensaje.replace(/[&<>"']/g, (ch) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\"": "&quot;",
        "'": "&#39;",
      }[ch]))}</pre>
    </div>
  `;

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: CONTACT_FROM,
      to: [CONTACT_TO],
      reply_to: email,
      subject,
      html,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return jsonResponse({ ok: false, error: "resend_error", detail: text.slice(0, 300) }, 502);
  }

  return jsonResponse({ ok: true });
});
