PRAGMA foreign_keys = false;
CREATE TABLE tmp_users (
	id INTEGER PRIMARY KEY NOT NULL,
	key_id UNSIGNED BIG INT NOT NULL UNIQUE
);
INSERT INTO tmp_users
    SELECT id, key_id
    FROM users;
DROP TABLE users;
ALTER TABLE tmp_users RENAME TO users;
PRAGMA foreign_key_check;
PRAGMA foreign_keys = true;
