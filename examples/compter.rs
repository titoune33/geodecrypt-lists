//! Compte les entrées d'un fichier de sanctions et affiche l'empreinte.
//!
//! ```bash
//! cargo run --example compter -- sdn.csv
//! ```

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let chemin = match args.next() {
        Some(c) => c,
        None => {
            eprintln!("usage : compter <fichier.csv>");
            return ExitCode::from(2);
        }
    };

    let contenu = match std::fs::read_to_string(&chemin) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("lecture impossible : {e}");
            return ExitCode::FAILURE;
        }
    };

    match geodecrypt_lists::lire(&chemin, &contenu) {
        Ok(lecture) => {
            println!("source     : {}", lecture.source.code());
            println!("lignes     : {}", lecture.lignes);
            println!("entrées    : {}", lecture.entrees.len());
            println!("rejets     : {}", lecture.rejets);
            println!("empreinte  : {}", lecture.empreinte);
            let avec_alias = lecture.entrees.iter().filter(|e| !e.alias.is_empty()).count();
            println!("avec alias : {avec_alias}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("format non reconnu : {e}");
            ExitCode::FAILURE
        }
    }
}
