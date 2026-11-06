use super::*;

pub(super) const STATUSES: [&str; 7] = [
    "unplanned",
    "wantToRead",
    "reading",
    "paused",
    "finished",
    "doneEnough",
    "abandoned",
];
pub(super) fn fields(kind: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match kind {
        "addBook" => (
            &["id", "title", "creator"],
            &[
                "id",
                "title",
                "creator",
                "isbn",
                "pages",
                "coverID",
                "publicationYear",
                "catalogKey",
            ],
        ),
        "editBook" => (
            &["id"],
            &[
                "id",
                "title",
                "creator",
                "isbn",
                "pages",
                "coverID",
                "publicationYear",
                "catalogKey",
                "expect",
            ],
        ),
        "deleteBook" | "deleteNote" => (&["id"], &["id", "expect"]),
        "setPlan" => (
            &["id", "status"],
            &["id", "status", "started", "finished", "reread", "expect"],
        ),
        "position" => (&["id", "fraction"], &["id", "fraction", "page"]),
        "addNote" => (
            &["id", "book", "text"],
            &["id", "book", "text", "quote", "location"],
        ),
        "editNote" => (&["id", "text"], &["id", "text", "expect"]),
        "resolveNote" => (
            &["id", "text", "expect", "resolves"],
            &["id", "text", "expect", "resolves"],
        ),
        "setCopyLoan" => (
            &["id", "status", "requestID"],
            &[
                "id",
                "status",
                "requestID",
                "reflection",
                "proposal",
                "expect",
            ],
        ),
        _ => return None,
    })
}
pub(super) fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
}
pub(super) fn day(s: &str) -> bool {
    if s.len() != 10
        || s.as_bytes()[4] != b'-'
        || s.as_bytes()[7] != b'-'
        || !s
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return false;
    }
    let y = s[..4].parse::<u32>().unwrap_or(0);
    let m = s[5..7].parse::<usize>().unwrap_or(0);
    let d = s[8..].parse::<u32>().unwrap_or(0);
    let days = [
        0,
        31,
        if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            29
        } else {
            28
        },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    y > 0 && m > 0 && m <= 12 && d > 0 && d <= days[m]
}
fn integer(v: &Value) -> bool {
    v.as_i64()
        .is_some_and(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
}
/// Validate a books command, including UTF-8 byte limits and Gregorian calendar days.
/// Unknown properties are accepted and retained as extensions.
pub fn validate(kind: &str, payload: &Value) -> bool {
    let Some((required, defined)) = fields(kind) else {
        return false;
    };
    let Some(p) = payload.as_object() else {
        return false;
    };
    if required.iter().any(|k| !p.contains_key(*k)) {
        return false;
    }
    p.iter().all(|(k, v)| {
        if !defined.contains(&k.as_str()) {
            return true;
        }
        if v.is_null() {
            return match k.as_str() {
                "expect" => kind != "resolveNote",
                "isbn" | "pages" | "coverID" | "publicationYear" | "catalogKey" | "started"
                | "finished" | "page" | "quote" | "location" | "reflection" | "proposal" => true,
                _ => false,
            };
        }
        match k.as_str() {
            "id" | "book" | "requestID" | "expect" => v.as_str().is_some_and(valid_id),
            "title" => v
                .as_str()
                .is_some_and(|s| !s.trim().is_empty() && s.len() <= 16384),
            "creator" | "location" => v.as_str().is_some_and(|s| s.len() <= 4096),
            "text" | "quote" | "reflection" => v.as_str().is_some_and(|s| s.len() <= 262144),
            "isbn" | "catalogKey" => v.as_str().is_some_and(|s| s.len() <= 4096),
            "pages" => integer(v) && v.as_i64().is_some_and(|n| n > 0),
            "page" => integer(v) && v.as_i64().is_some_and(|n| n >= 0),
            "coverID" | "publicationYear" => integer(v),
            "fraction" => v
                .as_f64()
                .is_some_and(|n| n.is_finite() && (0.0..=1.0).contains(&n)),
            "status" => v.as_str().is_some_and(|s| {
                if kind == "setCopyLoan" {
                    ["needsReturn", "returned"].contains(&s)
                } else {
                    STATUSES.contains(&s)
                }
            }),
            "started" | "finished" => v.as_str().is_some_and(day),
            "reread" => v.is_boolean(),
            "resolves" => v.as_array().is_some_and(|a| {
                a.iter().all(|v| v.as_str().is_some_and(valid_id))
                    && a.windows(2).all(|w| w[0].as_str() < w[1].as_str())
            }),
            _ => true,
        }
    })
}
pub(super) fn operations() -> Vec<Spec> {
    ["addBook","editBook","deleteBook","setPlan","position","addNote","editNote","resolveNote","deleteNote","setCopyLoan"].into_iter().map(|kind| {
        let (required,defined)=fields(kind).unwrap_or((&[],&[]));
        let mut properties=Map::new();
        for k in defined {
            let mut schema=match *k {
                "id"|"book"|"requestID"|"expect"=>json!({"type":"string","minLength":1,"maxLength":1024,"x-maxUtf8Bytes":1024,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+$"}),
                "pages"|"page"|"coverID"|"publicationYear"=>json!({"type":"integer","minimum":-9007199254740991i64,"maximum":9007199254740991i64}),
                "fraction"=>json!({"type":"number","minimum":0,"maximum":1}),
                "status"=>if kind=="setCopyLoan" {json!({"type":"string","enum":["needsReturn","returned"]})} else {json!({"type":"string","enum":STATUSES})},
                "started"|"finished"=>json!({"type":"string","format":"date"}),
                "reread"=>json!({"type":"boolean","default":false}),
                "resolves"=>json!({"type":"array","items":{"type":"string","minLength":1,"maxLength":1024},"uniqueItems":true,"description":"Exact sorted set of observed alternative revisions"}),
                "proposal"=>json!({}),
                _=> {let max=match *k {"title"=>16384,"text"|"quote"|"reflection"=>262144,_=>4096}; json!({"type":"string","maxLength":max,"x-maxUtf8Bytes":max})},
            };
            if *k=="pages" {schema["minimum"]=json!(1);}
            if *k=="page" {schema["minimum"]=json!(0);}
            if *k=="title" {schema["minLength"]=json!(1);schema["pattern"]=json!("\\S");}
            if ["expect","isbn","pages","coverID","publicationYear","catalogKey","started","finished","page","quote","location","reflection"].contains(k) && !(*k=="expect" && kind=="resolveNote") {schema=json!({"anyOf":[schema,{"type":"null"}]});}
            properties.insert((*k).into(),schema);
        }
        Spec{name:kind.into(),description:match kind {
            "addBook"=>"Add a book once with an unplanned reading",
            "editBook"=>"Patch metadata against the metadata head; null clears nullable fields",
            "deleteBook"=>"Permanently tombstone a book and hide its notes; compare activity head",
            "setPlan"=>"Update the current reading or append a reread; compare plan head",
            "position"=>"Report a reading position, including backwards movement",
            "addNote"=>"Add a note to a live book",
            "editNote"=>"Replace note text; stale text remains an attributed alternative",
            "resolveNote"=>"Resolve exactly the observed head and sorted alternative revisions",
            "deleteNote"=>"Permanently tombstone a note",
            _=>"App/device confirmed copy-loan action with a signer-scoped request receipt",
        }.into(),input_schema:json!({"type":"object","required":required,"properties":properties,"additionalProperties":true,"x-colophon-books-kind":kind,"x-colophon-member-kinds":if kind=="setCopyLoan" {json!(["app","device"])}else{json!(["app","device","agent","server"])}})}
    }).collect()
}
