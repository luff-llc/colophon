use colophon_core::domain::module;
fn main() {
    let values: Vec<_> = [
        "reading.books",
        "listening.podcasts",
        "reading.saved",
        "notes",
    ]
    .iter()
    .map(|name| {
        let m = module(name).expect("Built-in domain exists");
        serde_json::json!({"namespace":name,"operations":m.operations(),"queries":m.queries()})
    })
    .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&values).expect("Schemas are JSON")
    );
}
