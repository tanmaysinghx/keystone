-- Who did it from where: the client IP (the socket peer, or X-Forwarded-For from a trusted proxy)
-- and its User-Agent, recorded with every vault event.
ALTER TABLE audit_events ADD COLUMN ip TEXT;
ALTER TABLE audit_events ADD COLUMN user_agent TEXT;
