# geodecrypt-lists

Parseurs des trois listes de sanctions utilisées en contrôle export : **OFAC SDN**
(États-Unis), **liste consolidée de l'Union européenne** et **liste du Conseil de
sécurité de l'ONU**. Du CSV officiel vers une structure comparable, avec la
provenance et une empreinte vérifiable.

```rust
use geodecrypt_lists::lire;

let lecture = lire("sdn.csv", &std::fs::read_to_string("sdn.csv")?)?;
println!("{} entrées, empreinte {}", lecture.entrees.len(), lecture.empreinte);
```

## Pourquoi cette bibliothèque existe

Chaque équipe qui fait du criblage réécrit son parseur de listes, et se trompe
toujours au même endroit :

| Source | Le piège |
| --- | --- |
| OFAC SDN | le marqueur de colonne vide est `-0-`, pas une chaîne vide ; les alias sont collés dans la cellule du marqueur (`a.k.a. 'BNC'.`) |
| Union européenne | le séparateur dépend de la langue du fichier (`;` en français, `,` en anglais), et **une ligne par alias** : sans regroupement une entité apparaît vingt fois |
| ONU | plus de CSV depuis 2026 : la liste consolidée n'existe qu'en XML, et le nom se recompose à partir de quatre colonnes de prénoms |

Une entrée manquée ne provoque pas d'erreur visible : le criblage répond
« rien trouvé », ce qui est exactement le résultat qu'on ne peut pas se
permettre.

## Ce que fait la bibliothèque

- `lire(nom_fichier, contenu)` : devine la source d'après le nom, sinon d'après
  l'en-tête, puis renvoie une [`Lecture`].
- `lire_ofac`, `lire_ue`, `lire_onu_xml` : lecture explicite, quand on sait ce
  qu'on envoie.
- `empreinte(contenu)` : SHA-256 hexadécimal du fichier lu. C'est la pièce qui
  rend une lecture opposable : « le 16 novembre, la liste dont l'empreinte était
  `…` a été lue ».
- `Lecture` porte aussi `lignes` (parcourues) et `rejets` (lignes au découpage
  douteux, écartées plutôt que stockées fausses).

## Ce qu'elle ne fait pas

Aucun scoring, aucun seuil de similarité, aucun verdict, aucune clause
contractuelle. Le rapprochement flou et la décision restent dans le produit :
une bibliothèque de parsing doit être ennuyeuse et prévisible.

## Résultats sur les fichiers officiels

Mesurés le 16 novembre 2026, avec `cargo run --example compter -- <fichier>` :

| Fichier | Lignes | Entrées | Rejets | Temps |
| --- | ---: | ---: | ---: | ---: |
| `SDN.CSV` (OFAC) | 19 565 | 19 560 | 4 | < 1 s |
| `consolidated_fr.csv` (UE) | 44 043 | 6 269 entités (44 043 alias regroupés) | 215 | < 1 s |
| `consolidated.xml` (ONU) | 1 007 | 1 007 | 0 | < 1 s |

## Installation

```toml
[dependencies]
geodecrypt-lists = "0.1"
```

Les seules dépendances sont `sha2` (empreinte) et la bibliothèque standard.

## Sources officielles

- OFAC : `https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV`
- Union européenne : `https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content?token=…`
- ONU : `https://scsanctions.un.org/resources/xml/en/consolidated.xml`

Ces URL bougent. Le dépôt ne redistribue **aucune donnée** : il ne contient que
du code et des fixtures synthétiques.

## Tests

```bash
cargo test
```

Les tests couvrent les trois formats, le marqueur `-0-`, les deux séparateurs de
l'Union, les noms entre guillemets contenant une virgule, le regroupement des
alias et l'erreur explicite sur un en-tête inconnu.

## Licence

Apache-2.0. Voir `LICENSE`. La licence Apache plutôt que MIT parce qu'elle
contient une concession de brevet explicite, ce qui compte quand une banque ou
un industriel doit valider la dépendance.

## Contributions

Les fixtures réelles ne sont pas versionnées : pour reproduire un bogue, joindre
un extrait anonymisé de trois lignes et le nom de la source.
