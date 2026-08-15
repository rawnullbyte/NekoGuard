use serde_json::Value;

/// Recursively orders object keys in-place while preserving array order.
pub fn sort_json_object_keys(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = std::mem::take(object).into_iter().collect();
            for (_, value) in &mut entries {
                sort_json_object_keys(value);
            }
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            object.extend(entries);
        }
        Value::Array(values) => {
            for value in values {
                sort_json_object_keys(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::sort_json_object_keys;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_recursively_without_reordering_arrays() {
        let mut value = json!({
            "z": {"b": 2, "a": 1},
            "a": [{"d": 4, "c": 3}, "unchanged"],
            "m": null
        });

        sort_json_object_keys(&mut value);

        assert_eq!(
            value.to_string(),
            r#"{"a":[{"c":3,"d":4},"unchanged"],"m":null,"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn leaves_scalar_values_unchanged() {
        let mut value = json!([true, false, 42, "text", null]);

        sort_json_object_keys(&mut value);

        assert_eq!(value, json!([true, false, 42, "text", null]));
    }
}
