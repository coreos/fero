CREATE TABLE hsm_logs (
    id INTEGER PRIMARY KEY NOT NULL,
    hsm_index INTEGER NOT NULL UNIQUE,
    command INTEGER NOT NULL,
    data_length INTEGER NOT NULL,
    session_key INTEGER NOT NULL,
    target_key INTEGER NOT NULL,
    second_key INTEGER NOT NULL,
    result INTEGER NOT NULL,
    systick INTEGER NOT NULL,
    hash BLOB NOT NULL
);

CREATE TABLE fero_logs (
    id INTEGER PRIMARY KEY NOT NULL,
    request_type TEXT CHECK(request_type in ('sign', 'threshold', 'weight', 'add_secret', 'add_user')) NOT NULL,
    timestamp DATETIME NOT NULL,
    result TEXT CHECK(result in ('success', 'failure')) NOT NULL,
    hsm_index_start INTEGER NOT NULL,
    hsm_index_end INTEGER NOT NULL,
    identification BLOB,
    hash BLOB NOT NULL,

    FOREIGN KEY(hsm_index_start) REFERENCES hsm_logs(hsm_index),
    FOREIGN KEY(hsm_index_end) REFERENCES hsm_logs(hsm_index)
);
