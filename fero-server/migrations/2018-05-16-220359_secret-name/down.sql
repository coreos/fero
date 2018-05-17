PRAGMA foreign_keys = false;
CREATE TABLE tmp_secrets (
	id INTEGER PRIMARY KEY NOT NULL,
	key_id UNSIGNED BIG INT NOT NULL UNIQUE,
	threshold INTEGER NOT NULL,
    hsm_id INTEGER NOT NULL DEFAULT 0,
);
INSERT INTO tmp_secrets
    SELECT id, key_id, threshold, hsm_id
    FROM secrets;
DROP TABLE secrets;
ALTER TABLE tmp_secrets RENAME TO secrets;
PRAGMA foreign_key_check;
PRAGMA foreign_keys = true;
