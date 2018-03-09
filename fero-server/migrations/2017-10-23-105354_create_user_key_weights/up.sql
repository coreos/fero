CREATE TABLE user_secret_weights (
	id INTEGER PRIMARY KEY NOT NULL,
	secret_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	weight INTEGER NOT NULL,

	FOREIGN KEY(secret_id) REFERENCES secret_keys(id),
	FOREIGN KEY(user_id) REFERENCES user_keys(id)
)
