use mongodb::{
    bson::{doc, Binary, Bson},
    options::ClientOptions,
    Client, Collection,
};
use rocket::{get, http::Status, post, response::status, routes, State};
use serde::{Deserialize, Serialize};
use shuttle_runtime::{SecretStore, Secrets};
use std::time::{SystemTime, UNIX_EPOCH};
use tynkerbase_universal;

const DB_NAME: &str = "tyb-server-db";
const USER_AUTH_COL: &str = "user-auth";

#[derive(Debug, Serialize, Deserialize)]
struct UserAuthData {
    email: String,
    pass_sha256: String,
    creation_time: f64,
    salt: String,
    ngrok_aes: Option<Vec<u8>>,
}

impl UserAuthData {
    fn new(email: &str, pass_sha256: &str) -> Self {
        let start = SystemTime::now();
        let t = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let t = t.as_secs() as f64 + t.subsec_nanos() as f64 * 1e-9;

        let salt = tynkerbase_universal::crypt_utils::gen_salt();

        UserAuthData {
            email: email.to_string(),
            pass_sha256: pass_sha256.to_string(),
            creation_time: t,
            salt: salt,
            ngrok_aes: None,
        }
    }
}

async fn authenitcate_req(
    email: &str,
    pass_sha256: &str,
    client: &State<Client>,
) -> Result<UserAuthData, status::Custom<&'static str>> {
    let collection: Collection<UserAuthData> = client.database(DB_NAME).collection(USER_AUTH_COL);
    let res = collection.find_one(doc! {"email": email}).await;

    let res = match res {
        Ok(r) => r,
        Err(_) => {
            return Err(status::Custom(
                Status::InternalServerError,
                "Failed to access database",
            ))
        }
    };

    let res = match res {
        Some(r) => r,
        None => {
            return Err(status::Custom(
                Status::BadRequest,
                "No account with specified email exists",
            ))
        }
    };

    if res.pass_sha256 != pass_sha256 {
        return Err(status::Custom(Status::Forbidden, "inocrrect password"));
    }

    Ok(res)
}

#[get("/login?<email>&<pass_sha256>")]
async fn login(email: &str, pass_sha256: &str, client: &State<Client>) -> status::Custom<String> {
    let res = match authenitcate_req(email, pass_sha256, client).await {
        Ok(r) => r,
        Err(e) => return status::Custom(e.0, e.1.to_string()),
    };

    status::Custom(Status::Ok, res.salt.to_string())
}

#[get("/create-account?<email>&<pass_sha256>")]
async fn create_account(
    email: &str,
    pass_sha256: &str,
    client: &State<Client>,
) -> status::Custom<&'static str> {
    let collection: Collection<UserAuthData> = client.database(DB_NAME).collection(USER_AUTH_COL);
    let res = collection.find_one(doc! {"email": email}).await;

    match res {
        Ok(None) => {
            let new_user = UserAuthData::new(email, pass_sha256);
            let ins_res = collection.insert_one(new_user).await;
            if let Err(_e) = ins_res {
                return status::Custom(
                    Status::InternalServerError,
                    "unable to insert data into database",
                );
            }
            status::Custom(Status::Ok, "account created successfully")
        }
        Ok(Some(_)) => status::Custom(Status::BadRequest, "user already exists"),
        Err(_) => status::Custom(Status::InternalServerError, "Database query failed"),
    }
}

#[post("/save-ng-auth?<email>&<pass_sha256>", data = "<data>")]
async fn save_ng_auth(
    email: &str,
    pass_sha256: &str,
    data: Vec<u8>,
    client: &State<Client>,
) -> status::Custom<&'static str> {
    let _ = match authenitcate_req(email, pass_sha256, client).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let collection: Collection<UserAuthData> = client.database(DB_NAME).collection(USER_AUTH_COL);

    let update = Bson::Binary(Binary {
        subtype: mongodb::bson::spec::BinarySubtype::Generic,
        bytes: data,
    });
    let status = collection
        .update_one(doc! {"email": email}, doc! {"$set": {"ngrok_aes": update}})
        .await;
    if let Err(_) = status {
        return status::Custom(Status::BadRequest, "Error updating database");
    }

    status::Custom(Status::Ok, "success")
}

#[get("/get-ng-auth?<email>&<pass_sha256>")]
async fn get_ng_auth(
    email: &str,
    pass_sha256: &str,
    client: &State<Client>,
) -> status::Custom<Vec<u8>> {
    let res = match authenitcate_req(email, pass_sha256, client).await {
        Ok(r) => r,
        Err(e) => return status::Custom(e.0, e.1.as_bytes().to_vec()),
    };

    match res.ngrok_aes {
        Some(r) => status::Custom(Status::Ok, r),
        None => status::Custom(
            Status::NotFound,
            "ngrok key doesn't exist".to_string().into_bytes(),
        ),
    }
}

#[get("/")]
fn index() -> &'static str {
    "root"
}

#[shuttle_runtime::main]
async fn main(#[Secrets] secret_store: SecretStore) -> shuttle_rocket::ShuttleRocket {
    let mongo_auth_uri = secret_store
        .get("MONGO_AUTH_URI")
        .expect("Secret `MONGO_AUTH_URI` does not exist.");
    let client = ClientOptions::parse(&mongo_auth_uri)
        .await
        .expect("Unable to connect to mongo database");

    let client = Client::with_options(client).expect("Failed to build client");

    let rocket = rocket::build()
        .mount("/", routes![index])
        .mount("/auth", routes![login, create_account])
        .mount("/ngrok", routes![save_ng_auth, get_ng_auth])
        .manage(client);

    Ok(rocket.into())
}
