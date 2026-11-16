// Sends a notification by email through Resend.
//
// Called by the `tr_notifications_dispatch_email` database trigger with
// { notification_id } and an `x-webhook-secret` header.
//
// Edge function secrets (Dashboard -> Edge Functions -> Secrets):
//   RESEND_API_KEY   your Resend API key
//   RESEND_FROM      e.g. "Rcktz <notifications@yourdomain.com>" (verified domain)
//   APP_URL          e.g. "https://yourapp.com" (for links in the email)
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided automatically.
//
// Deploy with JWT verification off (the shared secret authenticates calls):
//   supabase functions deploy notification-email --no-verify-jwt

import { createClient } from 'npm:@supabase/supabase-js@2.45.4';

const RESEND_API_KEY = Deno.env.get('RESEND_API_KEY') ?? '';
const RESEND_FROM = Deno.env.get('RESEND_FROM') ?? '';
const APP_URL = (Deno.env.get('APP_URL') ?? '').replace(/\/$/, '');

const supabase = createClient(
  Deno.env.get('SUPABASE_URL')!,
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  { auth: { persistSession: false } },
);

type Recipient = {
  id: string;
  full_name: string | null;
  email: string | null;
  guardian_email: string | null;
  email_notifications: 'off' | 'fallback' | 'always';
};

const BATCH_SIZE = 100; // Resend batch limit

function escapeHtml(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function absoluteUrl(url: string | null): string | null {
  if (!url) return APP_URL || null;
  if (/^https?:\/\//i.test(url)) return url;
  return APP_URL ? `${APP_URL}${url.startsWith('/') ? '' : '/'}${url}` : null;
}

function renderEmail(opts: {
  clubName: string;
  playerName: string | null;
  title: string;
  body: string;
  link: string | null;
}) {
  const { clubName, playerName, title, body, link } = opts;
  const settings = APP_URL ? `${APP_URL}/settings` : null;
  const greeting = playerName ? `Hi ${escapeHtml(playerName.split(' ')[0])},` : 'Hi,';

  const html = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f8fafc;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1e293b">
  <div style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:24px">
    <p style="margin:0 0 4px;font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.05em">${escapeHtml(clubName)}</p>
    <h1 style="margin:0 0 16px;font-size:20px;color:#0f172a">${escapeHtml(title)}</h1>
    <p style="margin:0 0 12px">${greeting}</p>
    <p style="margin:0 0 20px;white-space:pre-line;line-height:1.5">${escapeHtml(body)}</p>
    ${link ? `<a href="${escapeHtml(link)}" style="display:inline-block;background:#059669;color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600">Open in app</a>` : ''}
  </div>
  ${settings ? `<p style="max-width:520px;margin:16px auto 0;font-size:12px;color:#94a3b8;text-align:center">You get these emails because you're a member of ${escapeHtml(clubName)}. <a href="${escapeHtml(settings)}" style="color:#64748b">Change email settings</a></p>` : ''}
</body></html>`;

  const text = [
    clubName,
    '',
    title,
    '',
    greeting,
    body,
    link ? `\nOpen in app: ${link}` : '',
    settings ? `\nChange email settings: ${settings}` : '',
  ].join('\n');

  return { html, text };
}

function json(status: number, data: unknown) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

Deno.serve(async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'Method not allowed' });

  // 1. Authenticate the caller (the database trigger)
  const { data: secret, error: secretError } = await supabase.rpc('get_notification_webhook_secret');
  if (secretError || !secret || req.headers.get('x-webhook-secret') !== secret) {
    return json(401, { error: 'Unauthorized' });
  }

  if (!RESEND_API_KEY || !RESEND_FROM) {
    return json(500, { error: 'RESEND_API_KEY / RESEND_FROM not configured' });
  }

  const { notification_id } = await req.json().catch(() => ({}));
  if (!notification_id) return json(400, { error: 'notification_id required' });

  // 2. Load the notification and its club
  const { data: notification, error: nError } = await supabase
    .from('notifications')
    .select('id, club_id, player_id, title, body, url, clubs(name)')
    .eq('id', notification_id)
    .single();
  if (nError || !notification) return json(404, { error: 'Notification not found' });

  const clubName = (notification.clubs as { name?: string } | null)?.name ?? 'Your club';

  // 3. Work out recipients: one player, or everyone in the club
  let query = supabase
    .from('players')
    .select('id, full_name, email, guardian_email, email_notifications')
    .neq('email_notifications', 'off');
  query = notification.player_id
    ? query.eq('id', notification.player_id)
    : query.eq('club_id', notification.club_id);

  const { data: players, error: pError } = await query;
  if (pError) return json(500, { error: pError.message });

  let recipients = (players ?? []) as Recipient[];

  // 'fallback' players only get email when they have no push subscription
  const fallbackIds = recipients.filter((p) => p.email_notifications === 'fallback').map((p) => p.id);
  if (fallbackIds.length) {
    const { data: subs } = await supabase
      .from('push_subscriptions')
      .select('player_id')
      .in('player_id', fallbackIds);
    const hasPush = new Set((subs ?? []).map((s) => s.player_id));
    recipients = recipients.filter((p) => p.email_notifications === 'always' || !hasPush.has(p.id));
  }

  // Skip anyone already emailed for this notification (retries / duplicates)
  const { data: already } = await supabase
    .from('notification_emails')
    .select('player_id')
    .eq('notification_id', notification.id)
    .eq('status', 'sent');
  const done = new Set((already ?? []).map((r) => r.player_id));

  const toSend = recipients
    .filter((p) => !done.has(p.id))
    .map((p) => ({ player: p, email: (p.email || p.guardian_email || '').trim() }))
    .filter((r) => r.email.includes('@'));

  if (!toSend.length) return json(200, { sent: 0, failed: 0 });

  // 4. Send through Resend's batch endpoint
  const link = absoluteUrl(notification.url);
  let sent = 0;
  let failed = 0;

  for (let i = 0; i < toSend.length; i += BATCH_SIZE) {
    const chunk = toSend.slice(i, i + BATCH_SIZE);
    const payload = chunk.map(({ player, email }) => {
      const { html, text } = renderEmail({
        clubName,
        playerName: player.full_name,
        title: notification.title,
        body: notification.body,
        link,
      });
      return { from: RESEND_FROM, to: [email], subject: notification.title, html, text };
    });

    let ids: (string | null)[] = chunk.map(() => null);
    let error: string | null = null;
    try {
      const res = await fetch('https://api.resend.com/emails/batch', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': `notification-${notification.id}-${i}`,
        },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        error = body?.message ?? `Resend error ${res.status}`;
      } else {
        ids = (body?.data ?? []).map((d: { id?: string }) => d?.id ?? null);
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }

    const rows = chunk.map(({ player, email }, idx) => ({
      notification_id: notification.id,
      player_id: player.id,
      club_id: notification.club_id,
      email,
      status: error ? 'failed' : 'sent',
      resend_id: ids[idx] ?? null,
      error,
    }));
    if (error) failed += chunk.length;
    else sent += chunk.length;

    await supabase.from('notification_emails').upsert(rows, { onConflict: 'notification_id,player_id' });
  }

  return json(200, { sent, failed });
});
