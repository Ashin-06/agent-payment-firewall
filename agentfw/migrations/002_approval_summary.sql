-- What the approver is shown, in words, with the payee's name and account resolved. The call is
-- refused if this no longer matches at execution, so people approve what will actually happen.
ALTER TABLE approvals ADD COLUMN summary TEXT
