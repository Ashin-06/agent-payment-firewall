-- When a scheduled payment goes out, in the bank's clock (epoch seconds). Until then the customer can undo it.
ALTER TABLE approvals ADD COLUMN release_at BIGINT
