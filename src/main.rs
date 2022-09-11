use jmap_client::client::{Client, Credentials};
use rocksdb::{Options, DB};

fn main() {
    //.connect("https://mail.stalw.art:8080")
    /*let mut client = Client::new()
    .credentials(Credentials::basic("mauro@stalw.art", "fNmWWGq79viDPN9N"))
    .connect("http://localhost:8080")
    .unwrap();*/
    let client = Client::new()
        .credentials(Credentials::basic("demo@stalw.art", "demo"))
        .connect("https://jmap.cloud:8443")
        .unwrap();
    client.email_get("pepe", None::<Vec<_>>).unwrap();

    // NB: db is automatically closed at end of lifetime
    let path = "_path_for_rocksdb_storage";
    {
        let db = DB::open_default(path).unwrap();
        db.put(b"my key", b"my value").unwrap();
        match db.get(b"my key") {
            Ok(Some(value)) => println!("retrieved value {}", String::from_utf8(value).unwrap()),
            Ok(None) => println!("value not found"),
            Err(e) => println!("operational problem encountered: {}", e),
        }
        db.delete(b"my key").unwrap();
    }
    let _ = DB::destroy(&Options::default(), path);
}
