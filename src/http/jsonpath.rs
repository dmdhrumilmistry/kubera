//! Dot-path lookups into JSON values.
//!
//! * `a.b.c`     - object keys
//! * `items.0`   - array index
//! * `items.*.id`- map over every array element / object value
//! * `$` or ``   - the whole document (a leading `$.` is ignored)

use serde_json::Value;

pub fn get(v: &Value, path: &str) -> Option<Value> {
    let path = path.trim();
    let path = path
        .strip_prefix("$.")
        .or_else(|| path.strip_prefix('$'))
        .unwrap_or(path);
    if path.is_empty() {
        return Some(v.clone());
    }
    let segs: Vec<&str> = path.split('.').collect();
    walk(v, &segs)
}

fn walk(v: &Value, segs: &[&str]) -> Option<Value> {
    let Some((head, rest)) = segs.split_first() else {
        return Some(v.clone());
    };
    if *head == "*" {
        let items: Vec<&Value> = match v {
            Value::Array(a) => a.iter().collect(),
            Value::Object(o) => o.values().collect(),
            _ => return None,
        };
        return Some(Value::Array(
            items.into_iter().filter_map(|i| walk(i, rest)).collect(),
        ));
    }
    let next = match v {
        Value::Object(o) => o.get(*head)?,
        Value::Array(a) => a.get(head.parse::<usize>().ok()?)?,
        _ => return None,
    };
    walk(next, rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn paths() {
        let d = json!({"a": {"b": [ {"id": 1}, {"id": 2} ]}, "ok": true});
        assert_eq!(get(&d, "ok"), Some(json!(true)));
        assert_eq!(get(&d, "$.a.b.1.id"), Some(json!(2)));
        assert_eq!(get(&d, "a.b.*.id"), Some(json!([1, 2])));
        assert_eq!(get(&d, "a.missing"), None);
        assert_eq!(get(&d, "$"), Some(d.clone()));
    }
}
