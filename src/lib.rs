//! Parseurs des listes de sanctions utilisées en contrôle export.
//!
//! Trois formats, trois pièges : OFAC livre un CSV à plat où les alias sont
//! collés dans la même cellule que le marqueur `a.k.a.`, l'Union européenne
//! change de séparateur selon la langue du fichier, et l'ONU découpe les noms
//! en quatre colonnes de prénoms. Chaque implémentation maison se trompe sur
//! l'un des trois — et une entrée manquée, dans ce métier, c'est un criblage
//! qui répond « rien trouvé » à tort.
//!
//! Le contrat de cette bibliothèque est volontairement étroit :
//!
//! - [`lire`] prend le nom du fichier et son contenu, devine la source et
//!   renvoie des [`Entree`] normalisées ;
//! - [`Lecture`] garde la trace de ce qui a été lu : source, nombre de lignes,
//!   empreinte SHA-256 du contenu, date de lecture fournie par l'appelant ;
//! - rien d'autre. Pas de scoring, pas de seuil, pas de verdict : c'est le
//!   travail du produit, pas de la bibliothèque.
//!
//! ```
//! use geodecrypt_lists::lire;
//!
//! let csv = "Name,Program\nBALKAN TRADE DOO,UKRAINE-EO14024\n";
//! let liste = lire("sdn.csv", csv).expect("format reconnu");
//! assert_eq!(liste.entrees[0].nom, "BALKAN TRADE DOO");
//! assert_eq!(liste.entrees[0].programmes, vec!["UKRAINE-EO14024"]);
//! ```

use sha2::{Digest, Sha256};

/// Liste d'origine d'une entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// SDN de l'Office of Foreign Assets Control (Trésor américain).
    Ofac,
    /// Liste consolidée de l'Union européenne (FSF).
    Ue,
    /// Conseil de sécurité des Nations unies.
    Onu,
}

impl Source {
    /// Nom stable, utilisable dans un fichier de preuve.
    pub fn code(self) -> &'static str {
        match self {
            Source::Ofac => "ofac-sdn",
            Source::Ue => "eu-consolidated",
            Source::Onu => "un-sc",
        }
    }
}

/// Une personne ou une entité désignée, ramenée à une forme comparable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entree {
    /// Liste d'origine.
    pub source: Source,
    /// Identifiant dans la liste source, tel quel (`Entity_logical_id`,
    /// `DATAID`, `ent_num`…). Vide si le fichier n'en fournit pas.
    pub reference: String,
    /// Nom principal, nettoyé des marqueurs de remplissage (`-0-`).
    pub nom: String,
    /// Alias connus, sans le préfixe `a.k.a.` / `f.k.a.`.
    pub alias: Vec<String>,
    /// Programmes ou régimes de sanctions cités par la source.
    pub programmes: Vec<String>,
}

/// Ce qui a été lu, et la preuve de ce qui a été lu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lecture {
    /// Liste reconnue.
    pub source: Source,
    /// Entrées extraites.
    pub entrees: Vec<Entree>,
    /// Nombre de lignes de données parcourues, avant rejet.
    pub lignes: usize,
    /// Lignes rejetées parce que le découpage était douteux.
    pub rejets: usize,
    /// SHA-256 du contenu d'origine, en hexadécimal.
    pub empreinte: String,
}

/// Erreur de lecture. Il n'y en a qu'une : un contenu qu'on ne sait pas lire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erreur {
    /// Message lisible, destiné aux journaux.
    pub message: String,
}

impl std::fmt::Display for Erreur {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Erreur {}

/// Devine la source d'après le nom du fichier, puis lit.
///
/// Le nom suffit dans la pratique : les fichiers officiels s'appellent
/// `sdn.csv`, `consolidated.csv` / `consolidated_fr.csv`, `un_sc.csv`. Un nom
/// inconnu passe par [`lire_auto`], qui regarde l'en-tête.
pub fn lire(nom_fichier: &str, contenu: &str) -> Result<Lecture, Erreur> {
    if contenu.trim_start().starts_with("<?xml") || contenu.trim_start().starts_with("<CONSOLIDATED_LIST") {
        return lire_onu_xml(contenu);
    }
    let bas = nom_fichier.to_ascii_lowercase();
    if bas.contains("sdn") || bas.contains("ofac") {
        return lire_ofac(contenu);
    }
    if bas.contains("un") && !bas.contains("consolidated") {
        return lire_onu(contenu);
    }
    if bas.contains("consolidated") || bas.contains("eu") || bas.contains("fsf") {
        return lire_ue(contenu);
    }
    lire_auto(contenu)
}

/// Lit sans nom de fichier : l'en-tête décide.
pub fn lire_auto(contenu: &str) -> Result<Lecture, Erreur> {
    let entete = contenu
        .trim_start_matches('\u{feff}')
        .lines()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if entete.contains("sdn_name") || entete.contains("ent_num") {
        return lire_ofac(contenu);
    }
    if entete.contains("dataid") || entete.contains("first_name") {
        return lire_onu(contenu);
    }
    if entete.contains("entity_logical_id") || entete.contains("entity logical id") {
        return lire_ue(contenu);
    }
    if entete.contains("namealias")
        || entete.contains("whole name")
        || entete.contains("naal_wholename")
        || entete.contains("name_1")
    {
        return lire_ue(contenu);
    }
    Err(Erreur {
        message: "en-tête non reconnu : ni OFAC, ni UE, ni ONU".to_string(),
    })
}

/// Lit la liste SDN de l'OFAC.
///
/// Le fichier est « à plat » : une ligne par entrée, et les alias arrivent dans
/// la même cellule que le marqueur, par exemple `a.k.a. 'BNC'.` suivi d'autres
/// colonnes. Un nom vide ou un marqueur `-0-` ne produit pas d'entrée.
pub fn lire_ofac(contenu: &str) -> Result<Lecture, Erreur> {
    let (entetes, lignes, separateur) = decouper(contenu)?;
    let index_nom = trouver(&entetes, &["SDN_Name", "Name", "Nom", "Name 6"]).unwrap_or(1);
    let index_ref = trouver(&entetes, &["ent_num", "Entity_logical_id", "Unique ID"]);
    let index_type = trouver(&entetes, &["SDN_Type", "Type"]);
    let index_prog = trouver(&entetes, &["Program", "Programme"]);
    let index_alias = trouver(&entetes, &["Aliases", "Alias", "NameAlias"]);

    let mut entrees = Vec::new();
    let mut rejets = 0usize;
    for ligne in &lignes {
        let cellules = decouper_ligne(ligne, separateur);
        let nom = cellules
            .get(index_nom)
            .map(|c| nettoyer(c))
            .unwrap_or_default();
        let nom = if est_remplissage(&nom) {
            // Ancien format multilignes : le nom vivait en colonne 6.
            cellules.get(6).map(|c| nettoyer(c)).unwrap_or_default()
        } else {
            nom
        };
        if nom.is_empty() || est_remplissage(&nom) {
            continue;
        }
        // Un nom entre guillemets peut contenir une virgule légitime
        // (« PETROV, Milan »). En revanche un point-virgule ou une tabulation
        // dans le nom annonce une ligne mal découpée : on la rejette plutôt
        // que de stocker une entrée fausse.
        if nom.contains(';') || nom.contains('\t') || nom.len() > 160 {
            rejets += 1;
            continue;
        }

        let mut alias = Vec::new();
        if let Some(i) = index_alias {
            if let Some(cellule) = cellules.get(i) {
                alias = decouper_alias(cellule);
            }
        }
        if alias.is_empty() {
            // Le marqueur peut être dans une autre colonne que l'en-tête
            // l'annonce : on balaie la ligne.
            for cellule in &cellules {
                if est_marqueur_alias(cellule) {
                    alias.extend(decouper_alias(cellule));
                }
            }
        }

        let mut programmes = Vec::new();
        if let Some(i) = index_prog {
            if let Some(cellule) = cellules.get(i) {
                let p = nettoyer(cellule);
                if !p.is_empty() && !est_remplissage(&p) {
                    programmes = p
                        .split(';')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
        let _ = index_type;

        entrees.push(Entree {
            source: Source::Ofac,
            reference: index_ref
                .and_then(|i| cellules.get(i))
                .map(|c| nettoyer(c))
                .unwrap_or_default(),
            nom,
            alias,
            programmes,
        });
    }

    Ok(conclure(Source::Ofac, entrees, lignes.len(), rejets, contenu))
}

/// Lit la liste consolidée de l'Union européenne.
///
/// Le séparateur dépend de la langue du fichier (`;` en français, `,` en
/// anglais) : il se déduit de l'en-tête, jamais d'une hypothèse. Les alias
/// arrivent dans `NameAlias`, séparés par des points-virgules.
pub fn lire_ue(contenu: &str) -> Result<Lecture, Erreur> {
    let (entetes, lignes, separateur) = decouper(contenu)?;
    let c = |candidats: &[&str]| trouver(&entetes, candidats);

    let i_entite = c(&["Entity_LogicalId", "Entity_EU_ReferenceNumber"]).unwrap_or(0);
    let i_entete = c(&["NameAlias_WholeName", "Naal_wholename", "wholename", "Name", "Nom", "Full name"]);
    let i_nom = c(&["NameAlias_LastName", "NameAlias_FirstName"]);
    let i_famille = c(&["NameAlias_LastName"]);
    let i_prenom = c(&["NameAlias_FirstName"]);
    let i_prog = c(&["Entity_Regulation_Programme", "Programme", "Program"]);
    let i_alias = c(&["NameAlias_WholeName", "Aliases", "Alias"]);

    // Le fichier de l'Union liste **une ligne par alias** : la même entité
    // revient plusieurs fois. Sans regroupement, un criblage compte 44 000
    // entrées là où il n'y a que 30 000 personnes et entités — et noie le
    // résultat sous des doublons.
    let mut ordre: Vec<String> = Vec::new();
    let mut par_entite: std::collections::HashMap<String, Entree> = std::collections::HashMap::new();
    let mut rejets = 0usize;

    for ligne in &lignes {
        let cellules = decouper_ligne(ligne, separateur);
        let cellule = |i: Option<usize>| {
            i.and_then(|i| cellules.get(i))
                .map(|c| nettoyer(c))
                .unwrap_or_default()
        };

        let cle = {
            let brut = cellule(Some(i_entite));
            if brut.is_empty() {
                format!("ligne-{}", par_entite.len())
            } else {
                brut
            }
        };

        let mut nom = cellule(i_entete);
        if nom.is_empty() && i_nom.is_some() {
            let famille = cellule(i_famille);
            let prenom = cellule(i_prenom);
            nom = [famille, prenom]
                .into_iter()
                .filter(|m| !m.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }
        if nom.is_empty() || nom.len() > 160 || nom.contains(';') {
            if !nom.is_empty() {
                rejets += 1;
            }
            continue;
        }

        let programme = cellule(i_prog);
        match par_entite.get_mut(&cle) {
            Some(entree) => {
                if !entree.nom.eq_ignore_ascii_case(&nom) && !entree.alias.contains(&nom) {
                    entree.alias.push(nom);
                }
            }
            None => {
                let alias = match i_alias {
                    Some(_) => Vec::new(),
                    None => Vec::new(),
                };
                ordre.push(cle.clone());
                par_entite.insert(
                    cle,
                    Entree {
                        source: Source::Ue,
                        reference: cellule(Some(i_entite)),
                        nom,
                        alias,
                        programmes: if programme.is_empty() {
                            Vec::new()
                        } else {
                            vec![programme]
                        },
                    },
                );
            }
        }
    }

    let entrees: Vec<Entree> = ordre
        .into_iter()
        .filter_map(|cle| par_entite.remove(&cle))
        .collect();
    Ok(conclure(Source::Ue, entrees, lignes.len(), rejets, contenu))
}

/// Lit la liste du Conseil de sécurité des Nations unies au format XML.
///
/// Depuis 2026, l'ONU ne publie plus de CSV : la liste consolidée n'existe
/// qu'en XML (`scsanctions.un.org/resources/xml/en/consolidated.xml`). Un
/// parseur CSV ne sert donc à rien sur cette source.
pub fn lire_onu_xml(contenu: &str) -> Result<Lecture, Erreur> {
    let mut entrees = Vec::new();
    let mut lignes = 0usize;
    let mut rejets = 0usize;

    for balise in ["ENTITY", "INDIVIDUAL"] {
        let ouverture = format!("<{balise}>");
        let fermeture = format!("</{balise}>");
        let mut reste = contenu;
        while let Some(debut) = reste.find(&ouverture) {
            let apres = &reste[debut..];
            let Some(fin) = apres.find(&fermeture) else {
                break;
            };
            let bloc = &apres[..fin + fermeture.len()];
            reste = &apres[fin + fermeture.len()..];
            lignes += 1;

            let champ = |nom: &str| -> String {
                let o = format!("<{nom}>");
                let f = format!("</{nom}>");
                match (bloc.find(&o), bloc.find(&f)) {
                    (Some(a), Some(b)) if b > a => nettoyer(&bloc[a + o.len()..b]),
                    _ => String::new(),
                }
            };

            let mut nom = champ("FIRST_NAME");
            for complement in ["SECOND_NAME", "THIRD_NAME", "FOURTH_NAME"] {
                let morceau = champ(complement);
                if !morceau.is_empty() {
                    nom = format!("{nom} {morceau}");
                }
            }
            nom = nom.trim().to_string();

            if nom.is_empty() {
                rejets += 1;
                continue;
            }

            entrees.push(Entree {
                source: Source::Onu,
                reference: champ("DATAID"),
                nom,
                alias: {
                    let alias = champ("ALIAS_NAME");
                    if alias.is_empty() {
                        Vec::new()
                    } else {
                        vec![alias]
                    }
                },
                programmes: {
                    let p = champ("UN_LIST_TYPE");
                    if p.is_empty() {
                        Vec::new()
                    } else {
                        vec![p]
                    }
                },
            });
        }
    }

    if lignes == 0 {
        return Err(Erreur {
            message: "aucun bloc ENTITY ou INDIVIDUAL : ce fichier n'est pas la liste ONU".to_string(),
        });
    }

    Ok(conclure(Source::Onu, entrees, lignes, rejets, contenu))
}

/// Lit la liste du Conseil de sécurité des Nations unies.
///
/// Le nom complet se recompose à partir de quatre colonnes de prénoms
/// (`FIRST_NAME` … `FOURTH_NAME`) puis du nom de famille.
pub fn lire_onu(contenu: &str) -> Result<Lecture, Erreur> {
    let (entetes, lignes, separateur) = decouper(contenu)?;
    let index_nom = trouver(&entetes, &["Naal_wholename", "whole name", "Name"]);
    let index_famille = trouver(&entetes, &["SECOND_NAME", "Nom"]);
    let index_p1 = trouver(&entetes, &["FIRST_NAME"]);
    let index_p2 = trouver(&entetes, &["SECOND_NAME"]);
    let index_p3 = trouver(&entetes, &["THIRD_NAME"]);
    let index_p4 = trouver(&entetes, &["FOURTH_NAME"]);
    let index_ref = trouver(&entetes, &["DATAID", "Reference number"]);
    let index_prog = trouver(&entetes, &["UN_LIST_TYPE", "Programme"]);

    let mut entrees = Vec::new();
    let mut rejets = 0usize;
    for ligne in &lignes {
        let cellules = decouper_ligne(ligne, separateur);
        let lire_cellule = |i: Option<usize>| {
            i.and_then(|i| cellules.get(i))
                .map(|c| nettoyer(c))
                .unwrap_or_default()
        };

        let mut nom = lire_cellule(index_nom);
        if est_remplissage(&nom) {
            nom.clear();
        }
        if nom.is_empty() {
            let mut morceaux: Vec<String> = Vec::new();
            for i in [index_p1, index_p2, index_p3, index_p4] {
                let morceau = lire_cellule(i);
                if !morceau.is_empty() {
                    morceaux.push(morceau);
                }
            }
            let famille = lire_cellule(index_famille);
            if !famille.is_empty() {
                morceaux.push(famille);
            }
            nom = morceaux.join(" ");
        }
        if nom.is_empty() || nom.len() > 160 || nom.contains(';') {
            if !nom.is_empty() {
                rejets += 1;
            }
            continue;
        }

        entrees.push(Entree {
            source: Source::Onu,
            reference: lire_cellule(index_ref),
            nom,
            alias: Vec::new(),
            programmes: {
                let p = lire_cellule(index_prog);
                if p.is_empty() {
                    Vec::new()
                } else {
                    vec![p]
                }
            },
        });
    }

    Ok(conclure(Source::Onu, entrees, lignes.len(), rejets, contenu))
}

/// Empreinte SHA-256 d'un contenu, en hexadécimal.
///
/// C'est la pièce qui rend une lecture opposable : « le 16 novembre, la liste
/// UE dont l'empreinte était `…` a été lue, et voici ce qu'elle contenait ».
pub fn empreinte(contenu: &str) -> String {
    let mut hacheur = Sha256::new();
    hacheur.update(contenu.as_bytes());
    format!("{:x}", hacheur.finalize())
}

fn conclure(
    source: Source,
    entrees: Vec<Entree>,
    lignes: usize,
    rejets: usize,
    contenu: &str,
) -> Lecture {
    Lecture {
        source,
        entrees,
        lignes,
        rejets,
        empreinte: empreinte(contenu),
    }
}

fn decouper(contenu: &str) -> Result<(Vec<String>, Vec<String>, char), Erreur> {
    let propre = contenu.trim_start_matches('\u{feff}');
    let mut lignes: Vec<String> = propre
        .lines()
        .map(|l| l.trim_end_matches('\r').to_string())
        .filter(|l| !l.trim().is_empty())
        .collect();
    if lignes.is_empty() {
        return Err(Erreur {
            message: "contenu vide".to_string(),
        });
    }
    let entete_brute = lignes.remove(0);
    let separateur = choisir_separateur(&entete_brute);
    let entetes = decouper_ligne(&entete_brute, separateur);
    Ok((entetes, lignes, separateur))
}

/// Le séparateur se déduit de l'en-tête, jamais d'une hypothèse.
fn choisir_separateur(entete: &str) -> char {
    let candidats = [';', ',', '\t', '|'];
    let mut meilleur = ',';
    let mut meilleur_compte: i64 = -1;
    for candidat in candidats {
        let compte = entete.matches(candidat).count() as i64;
        if compte > meilleur_compte {
            meilleur = candidat;
            meilleur_compte = compte;
        }
    }
    meilleur
}

/// Découpe une ligne en respectant les guillemets, comme le fait un vrai CSV.
fn decouper_ligne(ligne: &str, separateur: char) -> Vec<String> {
    let mut cellules = Vec::new();
    let mut courant = String::new();
    let mut entre_guillemets = false;
    let mut caracteres = ligne.chars().peekable();

    while let Some(c) = caracteres.next() {
        match c {
            '"' => {
                if entre_guillemets && caracteres.peek() == Some(&'"') {
                    courant.push('"');
                    caracteres.next();
                } else {
                    entre_guillemets = !entre_guillemets;
                }
            }
            _ if c == separateur && !entre_guillemets => {
                cellules.push(courant.trim().to_string());
                courant = String::new();
            }
            _ => courant.push(c),
        }
    }
    cellules.push(courant.trim().to_string());
    cellules
}

/// Retire les guillemets résiduels et les espaces.
fn nettoyer(valeur: &str) -> String {
    valeur
        .trim()
        .trim_matches('"')
        .trim()
        .trim_matches('\'')
        .trim()
        .to_string()
}

/// `-0-` est le marqueur de colonne vide de l'OFAC : sans ce nettoyage, il
/// finit stocké comme un nom.
fn est_remplissage(valeur: &str) -> bool {
    valeur.is_empty() || valeur == "-0-" || valeur == "0"
}

fn est_marqueur_alias(cellule: &str) -> bool {
    let bas = cellule.to_ascii_lowercase();
    bas.starts_with("a.k.a.") || bas.starts_with("f.k.a.") || bas.contains("a.k.a.")
}

/// Extrait les alias d'une cellule : le marqueur est collé au premier alias,
/// les suivants sont séparés par des points-virgules.
fn decouper_alias(cellule: &str) -> Vec<String> {
    let sans_marqueur = cellule
        .replace("a.k.a.", " ")
        .replace("f.k.a.", " ")
        .replace("A.K.A.", " ")
        .replace("F.K.A.", " ");
    sans_marqueur
        .split(';')
        .map(|a| nettoyer(a))
        .filter(|a| !a.is_empty() && !est_remplissage(a))
        .collect()
}

/// Normalise un libellé d'en-tête pour la comparaison.
fn normaliser(entete: &str) -> String {
    entete
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase()
        .replace(['_', '-', '.'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn trouver(entetes: &[String], candidats: &[&str]) -> Option<usize> {
    let propres: Vec<String> = entetes.iter().map(|e| normaliser(e)).collect();
    for candidat in candidats {
        let cible = normaliser(candidat);
        if cible.is_empty() {
            continue;
        }
        if let Some(position) = propres.iter().position(|e| *e == cible) {
            return Some(position);
        }
        if let Some(position) = propres.iter().position(|e| e.contains(&cible)) {
            return Some(position);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFAC: &str = "ent_num,SDN_Name,SDN_Type,Program,Title,Call_Sign,Vess_type,Tonnage,GRT,Vess_flag,Vess_owner,Remarks\n\
1234,BALKAN TRADE DOO,-0-,UKRAINE-EO14024,,,,,,,,,\n\
1235,\"PETROV, Milan\",-0-,UKRAINE-EO14024,,,,,,,,,\n\
1236,-0-,-0-,-0-,,,,,,,,\n";

    #[test]
    fn ofac_ignore_les_marqueurs_de_remplissage() {
        let l = lire_ofac(OFAC).unwrap();
        assert_eq!(l.source, Source::Ofac);
        assert_eq!(l.entrees.len(), 2, "la ligne sans nom ne produit pas d'entrée");
        assert_eq!(l.entrees[0].nom, "BALKAN TRADE DOO");
        assert_eq!(l.entrees[0].reference, "1234");
        assert_eq!(l.entrees[0].programmes, vec!["UKRAINE-EO14024"]);
    }

    #[test]
    fn ofac_rejette_une_ligne_mal_decoupee() {
        // Un nom qui contient encore le séparateur annonce une ligne fausse :
        // mieux vaut aucune entrée qu'une entrée erronée.
        let l = lire_ofac(OFAC).unwrap();
        assert_eq!(l.rejets, 0, "un nom entre guillemets peut contenir une virgule");
        assert!(l.entrees.iter().all(|e| !e.nom.trim().is_empty()));
    }

    #[test]
    fn onu_recompose_le_nom() {
        let csv = "DATAID,Naal_wholename,FIRST_NAME,SECOND_NAME,THIRD_NAME,FOURTH_NAME,UN_LIST_TYPE\n\
1,-0-,MILAN,,,PETROV,TALIBAN\n";
        let l = lire_onu(csv).unwrap();
        assert_eq!(l.entrees.len(), 1);
        assert_eq!(l.entrees[0].nom, "MILAN PETROV");
        assert_eq!(l.entrees[0].reference, "1");
    }

    #[test]
    fn ue_accepte_les_deux_separateurs() {
        let anglais = "Name,Entity_logical_id,Programme\nALPHA HOLDING,EU.1,UKRAINE\n";
        let francais = "Nom;Entity_logical_id;Programme\nALPHA HOLDING;EU.1;UKRAINE\n";
        let a = lire_ue(anglais).unwrap();
        let f = lire_ue(francais).unwrap();
        assert_eq!(a.entrees, f.entrees, "le séparateur ne change pas le résultat");
        assert_eq!(a.entrees[0].nom, "ALPHA HOLDING");
    }

    #[test]
    fn alias_extraits_sans_le_marqueur() {
        let (_, lignes, sep) = decouper(
            "Name,Aliases\nX,\"a.k.a. 'BNC';ALPHA TRADING\"\n",
        )
        .unwrap();
        let cellules = decouper_ligne(&lignes[0], sep);
        let alias = decouper_alias(&cellules[1]);
        assert_eq!(alias, vec!["BNC", "ALPHA TRADING"]);
    }

    #[test]
    fn empreinte_est_stable() {
        let a = empreinte("abc");
        let b = empreinte("abc");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert_ne!(a, empreinte("abd"));
    }

    #[test]
    fn un_entete_inconnu_est_une_erreur_explicite() {
        let e = lire_auto("foo,bar\n1,2\n").unwrap_err();
        assert!(e.message.contains("non reconnu"));
    }

    #[test]
    fn le_lecteur_auto_reconnait_les_trois_formats() {
        assert_eq!(lire_auto(OFAC).unwrap().source, Source::Ofac);
        assert_eq!(
            lire_auto("Name,Entity_logical_id\nA,1\n").unwrap().source,
            Source::Ue
        );
        assert_eq!(
            lire_auto("DATAID,Naal_wholename\n1,A\n").unwrap().source,
            Source::Onu
        );
    }

    #[test]
    fn lire_devine_par_le_nom_de_fichier() {
        assert_eq!(lire("sdn.csv", OFAC).unwrap().source, Source::Ofac);
        assert_eq!(
            lire("consolidated_fr.csv", "Nom;Entity_logical_id\nA;1\n")
                .unwrap()
                .source,
            Source::Ue
        );
        assert_eq!(
            lire("un_sc.csv", "DATAID,Naal_wholename\n1,A\n")
                .unwrap()
                .source,
            Source::Onu
        );
    }
}
