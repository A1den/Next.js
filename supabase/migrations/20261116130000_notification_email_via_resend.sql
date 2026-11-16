-- Email delivery for notifications via Resend
--
-- Every new row in public.notifications calls the `notification-email`
-- edge function (via pg_net). The function decides who gets an email,
-- based on each player's email_notifications setting:
--   'off'      never email
--   'fallback' email only if the player has no push subscription (default)
--   'always'   email even if they also get push
--
-- Requires: 20261116120000_notification_security_fixes.sql

------------------------------------------------------------------------------
-- Player preference
------------------------------------------------------------------------------

ALTER TABLE public.players
  ADD COLUMN IF NOT EXISTS email_notifications text NOT NULL DEFAULT 'fallback'
    CHECK (email_notifications IN ('off', 'fallback', 'always'));

------------------------------------------------------------------------------
-- Delivery log (one row per notification per player; also stops double sends)
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.notification_emails (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  notification_id uuid NOT NULL REFERENCES public.notifications(id) ON DELETE CASCADE,
  player_id uuid NOT NULL REFERENCES public.players(id) ON DELETE CASCADE,
  club_id uuid REFERENCES public.clubs(id) ON DELETE CASCADE,
  email text NOT NULL,
  status text NOT NULL CHECK (status IN ('sent', 'failed')),
  resend_id text,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (notification_id, player_id)
);

CREATE INDEX IF NOT EXISTS notification_emails_club_created_idx
  ON public.notification_emails (club_id, created_at DESC);

ALTER TABLE public.notification_emails ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Club admins read email log" ON public.notification_emails;
CREATE POLICY "Club admins read email log"
  ON public.notification_emails
  FOR SELECT
  TO authenticated
  USING (public.is_club_admin(club_id));

REVOKE ALL ON public.notification_emails FROM anon, authenticated;
GRANT SELECT ON public.notification_emails TO authenticated;
GRANT ALL ON public.notification_emails TO service_role;

------------------------------------------------------------------------------
-- Shared secret between the database trigger and the edge function.
-- Generated here so it never has to be copied by hand.
------------------------------------------------------------------------------

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM vault.secrets WHERE name = 'notification_webhook_secret') THEN
    PERFORM vault.create_secret(
      replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''),
      'notification_webhook_secret',
      'Authenticates database -> notification-email edge function calls'
    );
  END IF;

  -- Base URL of this project; change it in Vault on other environments.
  IF NOT EXISTS (SELECT 1 FROM vault.secrets WHERE name = 'project_url') THEN
    PERFORM vault.create_secret(
      'https://bnyjmqnrzpmtfoolmokv.supabase.co',
      'project_url',
      'Base URL used by database triggers to call edge functions'
    );
  END IF;
END $$;

-- The edge function calls this (with the service role) to check the header.
CREATE OR REPLACE FUNCTION public.get_notification_webhook_secret()
RETURNS text
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public', 'vault'
AS $$
  SELECT decrypted_secret FROM vault.decrypted_secrets
  WHERE name = 'notification_webhook_secret'
  LIMIT 1;
$$;

REVOKE ALL ON FUNCTION public.get_notification_webhook_secret() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_notification_webhook_secret() TO service_role;

------------------------------------------------------------------------------
-- Trigger: hand each new notification to the edge function
------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.dispatch_notification_email()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'vault', 'net'
AS $$
DECLARE
  v_url text;
  v_secret text;
BEGIN
  SELECT decrypted_secret INTO v_url
  FROM vault.decrypted_secrets WHERE name = 'project_url' LIMIT 1;
  SELECT decrypted_secret INTO v_secret
  FROM vault.decrypted_secrets WHERE name = 'notification_webhook_secret' LIMIT 1;

  IF v_url IS NULL OR v_secret IS NULL THEN
    RETURN NEW; -- not configured; never block the insert
  END IF;

  PERFORM net.http_post(
    url := v_url || '/functions/v1/notification-email',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-webhook-secret', v_secret
    ),
    body := jsonb_build_object('notification_id', NEW.id),
    timeout_milliseconds := 10000
  );

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.dispatch_notification_email() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS tr_notifications_dispatch_email ON public.notifications;
CREATE TRIGGER tr_notifications_dispatch_email
  AFTER INSERT ON public.notifications
  FOR EACH ROW
  EXECUTE FUNCTION public.dispatch_notification_email();
