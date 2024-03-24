use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use merlin::Transcript;
use serde::Deserialize;
use actix_web::get;

#[derive(Deserialize)]
struct ProofData {
    proof: Vec<u8>,
    committed_value: Vec<u8>,
}

#[post("/verify_proof")]
async fn verify_proof(data: web::Json<ProofData>) -> impl Responder {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let proof = match RangeProof::from_bytes(&data.proof) {
        Ok(proof) => proof,
        Err(e) => {
            println!("Error deserializing proof: {:?}", e);
            return HttpResponse::BadRequest().body("Invalid proof format");
        },
    };

    let compressed = CompressedRistretto::from_slice(&data.committed_value);
    let committed_value = match compressed.decompress() {
        Some(point) => point,
        None => {
            println!("Error decompressing committed value");
            return HttpResponse::BadRequest().body("Invalid committed value");
        },
    };

    let mut verifier_transcript = Transcript::new(b"ProveKnowledgeOfSecret");

    let verification_result = proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &committed_value.compress(),
        64,
    );

    match verification_result {
        Ok(_) => HttpResponse::Ok().body("Proof verified successfully"),
        Err(e) => {
            println!("Verification failed: {:?}", e);
            HttpResponse::BadRequest().body("Proof verification failed")
        },
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Server is running")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server is running at http://127.0.0.1:8080/");
    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(verify_proof)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
