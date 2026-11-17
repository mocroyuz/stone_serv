# Sous-traitants et transferts — Stone

> **Inventaire provisoire établi à partir des intégrations et de l'architecture du code.** La présence d'un SDK ou d'une intégration ne prouve pas qu'un fournisseur reçoit effectivement des données en production. Les régions, contrats et transferts doivent être vérifiés dans chaque tableau de bord et contrat.

| Fournisseur / service | Rôle technique identifié | Données susceptibles d'être traitées | Région / localisation | DPA / contrat | Transfert hors EEE |
|---|---|---|---|---|---|
| Supabase | Authentification, base de données, Storage | Comptes, contenus, profils, métadonnées, médias, données de sécurité | **eu-west-1 (confirmé via le projet Supabase Stone)** | **DPA à vérifier / archiver** | Région du projet en EEE ; support, sous-traitants et autres flux à vérifier |
| Render | Hébergement du backend | Requêtes API, données transitant par le serveur, journaux, secrets d'environnement | **Frankfurt (confirmé dans le service stone_serv)** | **DPA à vérifier / archiver** | Région du service en EEE ; journaux, support et sous-traitants à vérifier |
| Vercel | Hébergement frontend et proxy | Requêtes, métadonnées techniques, journaux de déploiement et d'exécution | **Non vérifiée** (accès au projet refusé par le périmètre de l'équipe) | **DPA à vérifier / archiver** | À déterminer après vérification des régions et journaux Vercel |
| Stripe | Paiements et abonnements | Données de facturation, identifiants clients et abonnements, factures | Selon configuration et services Stripe | **À vérifier / archiver** | À examiner dans le DPA et les flux |
| Meta | Connexion Instagram/Facebook | Identifiants de comptes, autorisations, contenu et données d'API | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Google | YouTube, Drive, Photos et OAuth | Identifiants, jetons, métadonnées et médias autorisés | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| TikTok | Connexion et publication | Identifiants, autorisations, médias et métadonnées | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Pinterest | Connexion et publication | Identifiants, autorisations, médias et métadonnées | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Threads | Connexion et publication | Identifiants, autorisations et contenu | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Dropbox | Import de fichiers | Métadonnées de fichiers et contenus sélectionnés | Selon compte Dropbox | Conditions et DPA applicables à vérifier | À examiner |
| Canva | Import/export de créations | Identifiants, créations et métadonnées | Selon compte Canva | Conditions et DPA applicables à vérifier | À examiner |

## Stockage des médias — constat technique

Le projet Supabase contient les buckets `avatars` et `post-media` marqués publics, ainsi que `tiktok-media` marqué privé. Les fichiers des deux buckets publics peuvent être récupérés par toute personne disposant de leur URL. La politique de confidentialité doit l'indiquer et l'équipe doit décider si les brouillons peuvent rester dans ces buckets. Le backend supprime les fichiers des préfixes utilisateur dans ces buckets lors de l'effacement du compte.

## Vérifications réalisées le 17 novembre 2026

- Projet Supabase « Stone » : statut actif, région `eu-west-1`.
- Service Render `stone_serv` : région `frankfurt`, dépôt `mocroyuz/stone_serv`, branche de déploiement `main`.
- Vercel : le contrôle de déploiement frontend est accessible via GitHub, mais l'accès aux paramètres de projet Vercel est refusé par le périmètre d'équipe ; aucune région de traitement ne peut être affirmée à partir de cette inspection.

## Actions requises

1. Exporter/archiver le DPA signé ou accepté de chaque fournisseur qui agit comme sous-traitant.
2. Documenter les sous-traitants ultérieurs et les changements de liste.
3. Relever la région réellement choisie pour chaque base, stockage, service et sauvegarde.
4. Vérifier où sont traités les journaux, le support, les sauvegardes et la télémétrie.
5. Pour chaque transfert hors EEE, identifier le pays, le destinataire, le rôle, le mécanisme juridique (adéquation ou clauses contractuelles types, selon le cas) et l'évaluation du transfert lorsque nécessaire.
6. Vérifier les paramètres de conservation et de suppression des fournisseurs.
7. Mettre à jour ce tableau avant chaque nouvelle intégration.

Ne pas annoncer « toutes les données sont hébergées dans l'UE » tant que chaque région et flux n'a pas été vérifié.
