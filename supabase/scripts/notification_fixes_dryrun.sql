-- DRY RUN: applies the notification security migration, tests it as a real
-- admin and a real member, then FAILS ON PURPOSE so everything is rolled back.
-- Expected outcome: an error starting with "DRYRUN_RESULTS" followed by the results.
-- Nothing is saved. Paste the whole file into the Supabase SQL editor and click Run.

-- Notification system fixes
--  1. Only club admins / team captains can create notifications for their club
--  2. Per-player read state for club-wide (broadcast) notifications
--  3. Players can no longer edit notification content, only their own read flag
--  4. Push subscriptions can only be registered against the player's own club
--  7. Indexes, a notification type, and created_by for accountability

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

-- Admin of the club, or captain of a team in the club
CREATE OR REPLACE FUNCTION public.can_send_club_notifications(target_club_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $$
  SELECT target_club_id IS NOT NULL AND (
    public.is_club_admin(target_club_id)
    OR EXISTS (
      SELECT 1 FROM public.teams t
      WHERE t.club_id = target_club_id AND t.captain_player_id = auth.uid()
    )
  );
$$;

-- True when the player belongs to the club
CREATE OR REPLACE FUNCTION public.is_player_in_club(p_player_id uuid, p_club_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.players p
    WHERE p.id = p_player_id AND p.club_id = p_club_id
  );
$$;

REVOKE ALL ON FUNCTION public.can_send_club_notifications(uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.is_player_in_club(uuid, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.can_send_club_notifications(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.is_player_in_club(uuid, uuid) TO authenticated, service_role;

------------------------------------------------------------------------------
-- 7. New columns + indexes
------------------------------------------------------------------------------

ALTER TABLE public.notifications
  ADD COLUMN IF NOT EXISTS type text NOT NULL DEFAULT 'general',
  ADD COLUMN IF NOT EXISTS created_by uuid DEFAULT auth.uid()
    REFERENCES auth.users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS notifications_player_created_idx
  ON public.notifications (player_id, created_at DESC)
  WHERE player_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS notifications_club_broadcast_created_idx
  ON public.notifications (club_id, created_at DESC)
  WHERE player_id IS NULL;

------------------------------------------------------------------------------
-- 1. Insert: only admins / captains, for their own club, to their own members
------------------------------------------------------------------------------

DROP POLICY IF EXISTS "Strict Notifications Insert" ON public.notifications;
CREATE POLICY "Strict Notifications Insert"
  ON public.notifications
  FOR INSERT
  TO authenticated
  WITH CHECK (
    public.can_send_club_notifications(club_id)
    AND (player_id IS NULL OR public.is_player_in_club(player_id, club_id))
  );

------------------------------------------------------------------------------
-- 3. Update: only your own targeted notifications, and only the read column
------------------------------------------------------------------------------

DROP POLICY IF EXISTS "Strict Notifications Update" ON public.notifications;
CREATE POLICY "Strict Notifications Update"
  ON public.notifications
  FOR UPDATE
  TO authenticated
  USING (player_id = auth.uid())
  WITH CHECK (player_id = auth.uid());

REVOKE UPDATE ON public.notifications FROM authenticated;
GRANT UPDATE (read) ON public.notifications TO authenticated;

-- Never needed by clients (TRUNCATE ignores RLS)
REVOKE TRUNCATE, TRIGGER, REFERENCES ON public.notifications FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.notifications FROM anon;

------------------------------------------------------------------------------
-- 2. Per-player read receipts
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.notification_reads (
  notification_id uuid NOT NULL REFERENCES public.notifications(id) ON DELETE CASCADE,
  player_id uuid NOT NULL REFERENCES public.players(id) ON DELETE CASCADE,
  read_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (notification_id, player_id)
);

CREATE INDEX IF NOT EXISTS notification_reads_player_idx
  ON public.notification_reads (player_id);

ALTER TABLE public.notification_reads ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Players read own receipts" ON public.notification_reads;
CREATE POLICY "Players read own receipts"
  ON public.notification_reads
  FOR SELECT
  TO authenticated
  USING (player_id = auth.uid());

-- Writes go through the RPCs below
REVOKE ALL ON public.notification_reads FROM anon, authenticated;
GRANT SELECT ON public.notification_reads TO authenticated;
GRANT ALL ON public.notification_reads TO service_role;

-- Keep the current look: existing broadcasts were already marked read,
-- so record them as read for every current member of that club.
INSERT INTO public.notification_reads (notification_id, player_id, read_at)
SELECT n.id, p.id, COALESCE(n.updated_at, n.created_at, now())
FROM public.notifications n
JOIN public.players p ON p.club_id = n.club_id
WHERE n.player_id IS NULL AND n.read IS TRUE
ON CONFLICT DO NOTHING;

-- Mark one notification read/unread for the calling player
CREATE OR REPLACE FUNCTION public.mark_notification_read(
  p_notification_id uuid,
  p_read boolean DEFAULT true
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $$
DECLARE
  v_uid uuid := auth.uid();
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.notifications n
    WHERE n.id = p_notification_id
      AND (n.player_id = v_uid
           OR (n.player_id IS NULL AND n.club_id = public.get_auth_club_id()))
  ) THEN
    RAISE EXCEPTION 'Notification not found';
  END IF;

  IF p_read THEN
    INSERT INTO public.notification_reads (notification_id, player_id)
    VALUES (p_notification_id, v_uid)
    ON CONFLICT DO NOTHING;
  ELSE
    DELETE FROM public.notification_reads
    WHERE notification_id = p_notification_id AND player_id = v_uid;
  END IF;

  -- Keep the legacy column in sync for notifications addressed to this player
  UPDATE public.notifications
  SET read = p_read
  WHERE id = p_notification_id AND player_id = v_uid;
END;
$$;

-- Mark everything visible to the calling player as read
CREATE OR REPLACE FUNCTION public.mark_all_notifications_read()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_club uuid := public.get_auth_club_id();
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  INSERT INTO public.notification_reads (notification_id, player_id)
  SELECT n.id, v_uid
  FROM public.notifications n
  WHERE n.player_id = v_uid
     OR (n.player_id IS NULL AND n.club_id = v_club)
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_count = ROW_COUNT;

  UPDATE public.notifications
  SET read = true
  WHERE player_id = v_uid AND read IS DISTINCT FROM true;

  RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION public.mark_notification_read(uuid, boolean) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.mark_all_notifications_read() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.mark_notification_read(uuid, boolean) TO authenticated;
GRANT EXECUTE ON FUNCTION public.mark_all_notifications_read() TO authenticated;

-- Inbox view: same columns as notifications, but `read` is per player.
-- security_invoker so the notifications/notification_reads RLS still applies.
CREATE OR REPLACE VIEW public.my_notifications
WITH (security_invoker = true)
AS
SELECT
  n.id,
  n.club_id,
  n.player_id,
  n.title,
  n.body,
  n.url,
  (r.read_at IS NOT NULL OR (n.player_id IS NOT NULL AND n.read IS TRUE)) AS read,
  n.created_at,
  n.updated_by,
  n.updated_at,
  n.type,
  n.created_by,
  r.read_at
FROM public.notifications n
LEFT JOIN public.notification_reads r
  ON r.notification_id = n.id AND r.player_id = auth.uid();

REVOKE ALL ON public.my_notifications FROM anon, authenticated;
GRANT SELECT ON public.my_notifications TO authenticated;

------------------------------------------------------------------------------
-- 4. Push subscriptions: club must be the player's own club
------------------------------------------------------------------------------

DROP POLICY IF EXISTS "Users can manage own push subscriptions" ON public.push_subscriptions;

CREATE POLICY "Users read own push subscriptions"
  ON public.push_subscriptions
  FOR SELECT
  TO authenticated
  USING (public.is_own_player_id(player_id));

CREATE POLICY "Users delete own push subscriptions"
  ON public.push_subscriptions
  FOR DELETE
  TO authenticated
  USING (public.is_own_player_id(player_id));

CREATE POLICY "Users add own push subscriptions"
  ON public.push_subscriptions
  FOR INSERT
  TO authenticated
  WITH CHECK (
    public.is_own_player_id(player_id)
    AND (club_id IS NULL OR public.is_player_in_club(player_id, club_id))
  );

CREATE POLICY "Users update own push subscriptions"
  ON public.push_subscriptions
  FOR UPDATE
  TO authenticated
  USING (public.is_own_player_id(player_id))
  WITH CHECK (
    public.is_own_player_id(player_id)
    AND (club_id IS NULL OR public.is_player_in_club(player_id, club_id))
  );

REVOKE TRUNCATE, TRIGGER, REFERENCES ON public.push_subscriptions FROM anon, authenticated;

-- RPC: ignore the club passed in, always use the player's own club,
-- and refuse callers without a player profile.
CREATE OR REPLACE FUNCTION public.upsert_push_subscription(
  p_player_id uuid,
  p_club_id uuid,
  p_endpoint text,
  p_p256dh text,
  p_auth text,
  p_user_agent text DEFAULT NULL::text
)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_user_email text := auth.jwt() ->> 'email';
  v_target_player_id uuid;
  v_club_id uuid;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT id, club_id INTO v_target_player_id, v_club_id
  FROM public.players
  WHERE id = p_player_id
    AND (id = v_user_id OR LOWER(email) = LOWER(v_user_email))
  LIMIT 1;

  IF v_target_player_id IS NULL THEN
    SELECT id, club_id INTO v_target_player_id, v_club_id
    FROM public.players
    WHERE id = v_user_id OR LOWER(email) = LOWER(v_user_email)
    ORDER BY (id = v_user_id) DESC
    LIMIT 1;
  END IF;

  IF v_target_player_id IS NULL THEN
    RAISE EXCEPTION 'No player profile for this account';
  END IF;

  INSERT INTO public.push_subscriptions (
    player_id, club_id, endpoint, p256dh, auth, user_agent, updated_at
  )
  VALUES (
    v_target_player_id, v_club_id, p_endpoint, p_p256dh, p_auth, p_user_agent, NOW()
  )
  ON CONFLICT (endpoint) DO UPDATE SET
    player_id = EXCLUDED.player_id,
    club_id = EXCLUDED.club_id,
    p256dh = EXCLUDED.p256dh,
    auth = EXCLUDED.auth,
    user_agent = EXCLUDED.user_agent,
    updated_at = NOW();

  RETURN json_build_object('success', true, 'player_id', v_target_player_id, 'club_id', v_club_id);
END;
$$;
CREATE TEMP TABLE _t(name text, result text) ON COMMIT DROP;
GRANT ALL ON _t TO authenticated;
DO $$
DECLARE
  v_admin uuid; v_member uuid; v_club uuid; v_other_club uuid; v_n uuid; v_bn uuid; c int;
BEGIN
  SELECT p.id, p.club_id INTO v_admin, v_club FROM players p WHERE p.role='admin' AND EXISTS(SELECT 1 FROM players m WHERE m.club_id=p.club_id AND m.role<>'admin') AND EXISTS(SELECT 1 FROM notifications n WHERE n.club_id=p.club_id) LIMIT 1;
  SELECT id INTO v_member FROM players WHERE club_id=v_club AND role<>'admin' AND NOT EXISTS(SELECT 1 FROM teams t WHERE t.captain_player_id=players.id) LIMIT 1;
  SELECT id INTO v_other_club FROM clubs WHERE id<>v_club LIMIT 1;
  SELECT id INTO v_bn FROM notifications WHERE club_id=v_club AND player_id IS NULL LIMIT 1;

  -- as member
  PERFORM set_config('request.jwt.claims', json_build_object('sub',v_member,'role','authenticated')::text, true);
  SET LOCAL ROLE authenticated;
  BEGIN INSERT INTO notifications(club_id,title,body) VALUES (v_club,'x','x'); INSERT INTO _t VALUES('member broadcast insert','ALLOWED (bad)');
  EXCEPTION WHEN others THEN INSERT INTO _t VALUES('member broadcast insert','blocked: '||SQLERRM); END;
  BEGIN UPDATE notifications SET title='hacked' WHERE id=v_bn; INSERT INTO _t VALUES('member edit title','ALLOWED (bad)');
  EXCEPTION WHEN others THEN INSERT INTO _t VALUES('member edit title','blocked: '||SQLERRM); END;
  UPDATE notifications SET read=false WHERE id=v_bn; GET DIAGNOSTICS c = ROW_COUNT;
  INSERT INTO _t VALUES('member flips shared read flag, rows changed', c::text);
  SELECT count(*) INTO c FROM my_notifications; INSERT INTO _t VALUES('member sees in my_notifications', c::text);
  SELECT count(*) INTO c FROM my_notifications WHERE read; INSERT INTO _t VALUES('  of which read (backfilled)', c::text);
  PERFORM mark_notification_read(v_bn, false);
  SELECT count(*) INTO c FROM my_notifications WHERE read; INSERT INTO _t VALUES('  read after marking one unread', c::text);
  SELECT mark_all_notifications_read() INTO c; INSERT INTO _t VALUES('mark_all_notifications_read returned', c::text);
  BEGIN INSERT INTO push_subscriptions(player_id,club_id,endpoint,p256dh,auth) VALUES (v_member,v_other_club,'https://test/x','k','a'); INSERT INTO _t VALUES('member push sub in other club','ALLOWED (bad)');
  EXCEPTION WHEN others THEN INSERT INTO _t VALUES('member push sub in other club','blocked: '||SQLERRM); END;
  BEGIN INSERT INTO push_subscriptions(player_id,club_id,endpoint,p256dh,auth) VALUES (v_member,v_club,'https://test/y','k','a'); INSERT INTO _t VALUES('member push sub own club','allowed');
  EXCEPTION WHEN others THEN INSERT INTO _t VALUES('member push sub own club','BLOCKED (bad): '||SQLERRM); END;
  BEGIN INSERT INTO push_subscriptions(player_id,club_id,endpoint,p256dh,auth) VALUES (v_member,v_club,'https://test/y','k2','a2') ON CONFLICT (endpoint) DO UPDATE SET p256dh=EXCLUDED.p256dh, updated_at=now(); INSERT INTO _t VALUES('member push upsert own club','allowed');
  EXCEPTION WHEN others THEN INSERT INTO _t VALUES('member push upsert own club','BLOCKED (bad): '||SQLERRM); END;
  PERFORM upsert_push_subscription(v_member, v_other_club, 'https://test/z','k','a');
  INSERT INTO _t SELECT 'rpc upsert with other club', CASE WHEN club_id=v_club THEN 'stored own club' ELSE 'STORED OTHER CLUB (bad)' END FROM push_subscriptions WHERE endpoint='https://test/z';
  RESET ROLE;
  PERFORM set_config('request.jwt.claims', json_build_object('sub',v_admin,'role','authenticated')::text, true);
  SET LOCAL ROLE authenticated;
  BEGIN INSERT INTO notifications(club_id,title,body,read,url) VALUES (v_club,'t','b',false,'/x') RETURNING id INTO v_n; INSERT INTO _t VALUES('admin broadcast insert','allowed');
  EXCEPTION WHEN others THEN INSERT INTO _t VALUES('admin broadcast insert','BLOCKED (bad): '||SQLERRM); END;
  BEGIN INSERT INTO notifications(club_id,title,body) VALUES (v_other_club,'t','b'); INSERT INTO _t VALUES('admin insert into other club','ALLOWED (bad)');
  EXCEPTION WHEN others THEN INSERT INTO _t VALUES('admin insert into other club','blocked: '||SQLERRM); END;
  SELECT count(*) INTO c FROM push_subscriptions WHERE club_id=v_club; INSERT INTO _t VALUES('admin can still list club subs', c::text);
  RESET ROLE;
END $$;

DO $x$ BEGIN RAISE EXCEPTION 'DRYRUN_RESULTS %', (SELECT json_agg(_t) FROM _t); END $x$;
