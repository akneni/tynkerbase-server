use shuttle_runtime::{Secrets, SecretStore};
use rocket::{
    get, 
    routes, 
    State, 
    response::status,
    http::Status,
};
use mongodb::{Client, options::ClientOptions, Collection, bson::doc};
use serde::{Serialize, Deserialize};
use tynkerbase_universal;
use std::time::{SystemTime, UNIX_EPOCH};

const DB_NAME: &str = "tyb-server-db";
const USER_AUTH_COL: &str = "user-auth";

#[derive(Debug, Serialize, Deserialize)]
struct UserAuthData {
    email: String,
    pass_sha256: String,
    creation_time: f64,
    salt: String,
}

impl UserAuthData {
    fn new(email: &str, pass_sha256: &str) -> Self {
        let start = SystemTime::now();
        let t = start.duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let t = t.as_secs() as f64 + t.subsec_nanos() as f64 * 1e-9;
        
        let salt = tynkerbase_universal::crypt_utils::gen_salt();

        UserAuthData {
            email: email.to_string(),
            pass_sha256: pass_sha256.to_string(),
            creation_time: t,
            salt: salt,
        }
    }
}

#[get("/login?<email>&<pass_sha256>")]
async fn login (email: &str, pass_sha256: &str, client: &State<Client>) -> status::Custom<String> {
    let collection: Collection<UserAuthData> = client.database(DB_NAME).collection(USER_AUTH_COL);
    let res = collection.find_one(doc!{"email": email})
        .await;

    match res {
        Ok(Some(user_auth_data)) => {
            if user_auth_data.pass_sha256 != pass_sha256  {
                return status::Custom(Status::Unauthorized, "Incorrect password".to_string())
            }

            return status::Custom(Status::Ok, user_auth_data.salt);
        },
        Ok(None) => return status::Custom(Status::BadRequest, "User not found".to_string()),
        Err(_) => return status::Custom(Status::InternalServerError, "Database query failed".to_string()),
    };
}

#[get("/create-account?<email>&<pass_sha256>")]
async fn create_account (email: &str, pass_sha256: &str, client: &State<Client>) -> status::Custom<&'static str> {
    let collection: Collection<UserAuthData> = client.database(DB_NAME).collection(USER_AUTH_COL);
    let res = collection.find_one(doc!{"email": email})
        .await;

    match res {
        Ok(None) => {
            let new_user = UserAuthData::new(email, pass_sha256);
            let ins_res = collection.insert_one(new_user).await;
            if let Err(_e) = ins_res {
                return status::Custom(Status::InternalServerError, "unable to insert data into database");
            }
            status::Custom(Status::Ok, "account created successfully")
        },
        Ok(Some(_)) => status::Custom(Status::BadRequest, "user already exists"),
        Err(_) => status::Custom(Status::InternalServerError, "Database query failed"),
    }
}

#[get("/")]
fn index() -> &'static str {
    "root"
}

#[shuttle_runtime::main]
async fn main(#[Secrets] secret_store: SecretStore) -> shuttle_rocket::ShuttleRocket {
    let mongo_auth_uri = secret_store.get("MONGO_AUTH_URI").expect("Secret `MONGO_AUTH_URI` does not exist.");
    let client = ClientOptions::parse(&mongo_auth_uri)
        .await
        .expect("Unable to connect to mongo database");

    let client = Client::with_options(client).expect("Failed to build client");

    let rocket = rocket::build()
        .mount("/", routes![index])
        .mount("/auth", routes![login, create_account])
        .manage(client);

    Ok(rocket.into())
}
