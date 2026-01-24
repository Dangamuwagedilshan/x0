-- Migration 008: Add autonomous_delegate_created webhook event type

-- Add the new enum value for autonomous delegate webhooks
ALTER TYPE webhook_event_type ADD VALUE IF NOT EXISTS 'autonomous_delegate_created';
