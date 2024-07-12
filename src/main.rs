mod schemas;

use bincode;
use futures::StreamExt;
use mongodb::{
    bson::{doc, Binary, Bson},
    options::ClientOptions,
    Client, Collection,
};
use rocket::{get, http::Status, post, response::status, routes, State};
use schemas::{Node, UserAuthData};
use shuttle_runtime::{SecretStore, Secrets};

const DB_NAME: &str = "tyb-server-db";
const USER_AUTH_COL: &str = "user-auth";
const NODES_COL: &str = "ng-addr";

async fn authenticate_req(
    email: &str,
    pass_sha256: &str,
    client: &State<Client>,
) -> Result<UserAuthData, status::Custom<String>> {
    let collection: Collection<UserAuthData> = client.database(DB_NAME).collection(USER_AUTH_COL);
    let res = collection.find_one(doc! {"email": email}).await;

    let res = match res {
        Ok(r) => r,
        Err(e) => {
            return Err(status::Custom(
                Status::InternalServerError,
                format!("Failed to access database -> {}", e),
            ))
        }
    };

    let res = match res {
        Some(r) => r,
        None => {
            return Err(status::Custom(
                Status::BadRequest,
                "No account with specified email exists".to_string(),
            ))
        }
    };

    if res.pass_sha256 != pass_sha256 {
        return Err(status::Custom(Status::Forbidden, "incorrect password".to_string()));
    }

    Ok(res)
}

#[get("/login?<email>&<pass_sha256>")]
async fn login(email: &str, pass_sha256: &str, client: &State<Client>) -> status::Custom<String> {
    let res = match authenticate_req(email, pass_sha256, client).await {
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
) -> status::Custom<String> {
    let _ = match authenticate_req(email, pass_sha256, client).await {
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
    if let Err(e) = status {
        return status::Custom(Status::BadRequest, format!("Error updating database -> {}", e));
    }

    status::Custom(Status::Ok, "success".to_string())
}

#[get("/get-ng-auth?<email>&<pass_sha256>")]
async fn get_ng_auth(
    email: &str,
    pass_sha256: &str,
    client: &State<Client>,
) -> status::Custom<Vec<u8>> {
    let res = match authenticate_req(email, pass_sha256, client).await {
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

#[post("/add-addr?<email>&<pass_sha256>", data = "<data>")]
async fn add_address(
    email: &str,
    pass_sha256: &str,
    data: Vec<u8>,
    client: &State<Client>,
) -> status::Custom<String> {
    match authenticate_req(email, pass_sha256, client).await {
        Ok(_) => {}
        Err(e) => return status::Custom(e.0, e.1.to_string()),
    }

    let collection: Collection<Node> = client.database(DB_NAME).collection(NODES_COL);

    let node: Node = match bincode::deserialize(&data) {
        Ok(n) => n,
        Err(e) => return status::Custom(Status::BadRequest, format!("data is in the incorrect format -> {}", e)),
    };

    // Check if node already exists.
    let res = collection.find_one(doc! {"node_id": &node.node_id}).await;

    if let Ok(None) = res {
        let res = collection.insert_one(node).await;
        if let Err(e) = res {
            return status::Custom(
                Status::InternalServerError,
                format!("failed to insert data to database -> {}", e),
            );
        }
    } else if let Ok(Some(_)) = res {
        let res = collection
            .update_one(doc! {"node_id": &node.node_id}, doc! {"$set": {"addr": &node.addr}})
            .await;
        if let Err(e) = res {
            return status::Custom(
                Status::InternalServerError,
                format!("failed to update data in database -> {}", e),
            );
        }
    } else if let Err(e) = res {
        return status::Custom(Status::InternalServerError, format!("failed to access database -> {}", e));
    }
    status::Custom(Status::Ok, "success".to_string())
}

#[get("/remove-addr?<email>&<pass_sha256>&<node_id>")]
async fn remove_address(
    email: &str,
    pass_sha256: &str,
    node_id: &str,
    client: &State<Client>,
) -> status::Custom<String> {
    match authenticate_req(email, pass_sha256, client).await {
        Ok(_) => {}
        Err(e) => return e,
    }

    let collection: Collection<Node> = client.database(DB_NAME).collection(NODES_COL);

    let res = collection.delete_one(doc! {"node_id": node_id}).await;
    if let Err(e) = res {
        return status::Custom(Status::InternalServerError, format!("failed to delete from db -> {}", e));
    }
    status::Custom(Status::Ok, "success".to_string())
}

#[get("/check-node-exists/id?<email>&<pass_sha256>&<node_id>")]
async fn check_node_exists_id(
    email: &str,
    pass_sha256: &str,
    node_id: &str,
    client: &State<Client>,
) -> status::Custom<String> {
    match authenticate_req(email, pass_sha256, client).await {
        Ok(_) => {}
        Err(e) => return e,
    }

    let collection: Collection<Node> = client.database(DB_NAME).collection(NODES_COL);

    let res = collection
        .find_one(doc! {"email": email, "node_id": node_id})
        .await
        .unwrap();

    if res.is_none() {
        return status::Custom(Status::Ok, "false".to_string());
    }
    status::Custom(Status::Ok, "true".to_string())
}

#[get("/check-node-exists/name?<email>&<pass_sha256>&<name>")]
async fn check_node_exists_name(
    email: &str,
    pass_sha256: &str,
    name: &str,
    client: &State<Client>,
) -> status::Custom<String> {
    match authenticate_req(email, pass_sha256, client).await {
        Ok(_) => {}
        Err(e) => return e,
    }

    let collection: Collection<Node> = client.database(DB_NAME).collection(NODES_COL);

    let res = collection
        .find_one(doc! {"email": email, "name": name})
        .await
        .unwrap();

    if res.is_none() {
        return status::Custom(Status::Ok, "false".to_string());
    }
    status::Custom(Status::Ok, "true".to_string())
}

#[get("/get-all-addrs?<email>&<pass_sha256>")]
async fn get_all_addresses(
    email: &str,
    pass_sha256: &str,
    client: &State<Client>,
) -> status::Custom<Vec<u8>> {
    match authenticate_req(email, pass_sha256, client).await {
        Ok(_) => {}
        Err(e) => return status::Custom(e.0, e.1.as_bytes().to_vec()),
    }

    let collection: Collection<Node> = client.database(DB_NAME).collection(NODES_COL);

    let cursor = collection.find(doc! {"email": email}).await;
    let mut cursor = match cursor {
        Ok(c) => c,
        Err(e) => {
            return status::Custom(
                Status::InternalServerError,
                format!("Failed to read from db -> {}", e).as_bytes().to_vec(),
            )
        }
    };

    let mut addresses: Vec<Node> = vec![];

    while let Some(Ok(doc)) = cursor.next().await {
        addresses.push(doc);
    }

    let bin = match bincode::serialize(&addresses) {
        Ok(b) => b,
        Err(e) => return status::Custom(Status::InternalServerError, format!("error serializing result -> {}", e).as_bytes().to_vec()),
    };

    status::Custom(Status::Ok, bin)
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
        .mount(
            "/ngrok",
            routes![
                save_ng_auth,
                get_ng_auth,
                add_address,
                remove_address,
                get_all_addresses,
                check_node_exists_name,
                check_node_exists_id,
            ],
        )
        .manage(client);

    Ok(rocket.into())
}
