table! {
    secrets (id) {
        id -> Integer,
        key_id -> Nullable<BigInt>,
        threshold -> Integer,
        hsm_id -> Integer,
        name -> Text,
    }
}

table! {
    user_secret_weights (id) {
        id -> Integer,
        secret_id -> Integer,
        user_id -> Integer,
        weight -> Integer,
    }
}

table! {
    users (id) {
        id -> Integer,
        key_id -> BigInt,
        key_data -> Binary,
    }
}

joinable!(user_secret_weights -> secrets (secret_id));
joinable!(user_secret_weights -> users (user_id));

table! {
    use diesel::sql_types::{Binary, Integer, Nullable, Timestamp};
    use fero_proto::log::{OperationResultMapping, OperationTypeMapping};

    fero_logs (id) {
        id -> Integer,
        request_type -> OperationTypeMapping,
        timestamp -> Timestamp,
        result -> OperationResultMapping,
        hsm_index_start -> Integer,
        hsm_index_end -> Integer,
        identification -> Nullable<Binary>,
        hash -> Binary,
    }
}

table! {
    hsm_logs (id) {
        id -> Integer,
        hsm_index -> Integer,
        command -> Integer,
        data_length -> Integer,
        session_key -> Integer,
        target_key -> Integer,
        second_key -> Integer,
        result -> Integer,
        systick -> Integer,
        hash -> Binary,
    }
}

allow_tables_to_appear_in_same_query!(
    secrets,
    user_secret_weights,
    users,
);
