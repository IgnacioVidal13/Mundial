import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE_KEY =
  Deno.env.get("SERVICE_ROLE_KEY") ??
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
  "";

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

function getBearerToken(req: Request) {
  const auth = req.headers.get("authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ ok: false, error: "method_not_allowed" }, 405);
  }

  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    return jsonResponse({ ok: false, error: "missing_config" }, 500);
  }

  const token = getBearerToken(req);
  if (!token) {
    return jsonResponse({ ok: false, error: "missing_auth" }, 401);
  }

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });

  const {
    data: { user },
    error: userError,
  } = await admin.auth.getUser(token);

  if (userError || !user) {
    return jsonResponse({ ok: false, error: "invalid_auth" }, 401);
  }

  const cleanupErrors: string[] = [];
  const cleanupTargets = [
    admin.from("album_amigos").delete().or(`owner_id.eq.${user.id},friend_id.eq.${user.id}`),
    admin.from("album_intercambios").delete().eq("owner_id", user.id),
    admin.from("progreso_album").delete().eq("id", user.id),
    admin.from("profiles").delete().eq("id", user.id),
  ];

  for (const query of cleanupTargets) {
    const { error } = await query;
    if (error) cleanupErrors.push(error.message);
  }

  const softDelete = await admin.auth.admin.deleteUser(user.id, true);
  if (softDelete.error) {
    return jsonResponse(
      {
        ok: false,
        error: "delete_failed",
        cleanup: cleanupErrors.slice(0, 5),
        soft_detail: softDelete.error.message,
      },
      500
    );
  }

  return jsonResponse({
    ok: true,
    deleted: "soft",
    cleanup: cleanupErrors.slice(0, 5),
  });
});
