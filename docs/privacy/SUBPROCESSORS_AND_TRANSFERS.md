# Sous-traitants et transferts — Stone

> **Inventaire provisoire établi à partir des intégrations et de l'architecture du code.** La présence d'un SDK ou d'une intégration ne prouve pas qu'un fournisseur reçoit effectivement des données en production. Les régions, contrats et transferts doivent être vérifiés dans chaque tableau de bord et contrat.

| Fournisseur / service | Rôle technique identifié | Données susceptibles d'être traitées | Région / localisation | DPA / contrat | Transfert hors EEE |
|---|---|---|---|---|---|
| Supabase | Authentification, base de données, Storage | Comptes, contenus, profils, métadonnées, médias, données de sécurité | **À vérifier dans le projet** | **À vérifier / archiver** | À déterminer selon région et support |
| Render | Hébergement du backend | Requêtes API, données transitant par le serveur, journaux, secrets d'environnement | **À vérifier dans le service** | **À vérifier / archiver** | À déterminer |
| Vercel | Hébergement frontend et proxy | Requêtes, métadonnées techniques, journaux de déploiement et d'exécution | **À vérifier dans le projet** | **À vérifier / archiver** | À déterminer |
| Stripe | Paiements et abonnements | Données de facturation, identifiants clients et abonnements, factures | Selon configuration et services Stripe | **À vérifier / archiver** | À examiner dans le DPA et les flux |
| Meta | Connexion Instagram/Facebook | Identifiants de comptes, autorisations, contenu et données d'API | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Google | YouTube, Drive, Photos et OAuth | Identifiants, jetons, métadonnées et médias autorisés | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| TikTok | Connexion et publication | Identifiants, autorisations, médias et métadonnées | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Pinterest | Connexion et publication | Identifiants, autorisations, médias et métadonnées | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Threads | Connexion et publication | Identifiants, autorisations et contenu | Selon plateforme | Conditions et DPA applicables à vérifier | À examiner |
| Dropbox | Import de fichiers | Métadonnées de fichiers et contenus sélectionnés | Selon compte Dropbox | Conditions et DPA applicables à vérifier | À examiner |
| Canva | Import/export de créations | Identifiants, créations et métadonnées | Selon compte Canva | Conditions et DPA applicables à vérifier | À examiner |

## Actions requises

1. Exporter/archiver le DPA signé ou accepté de chaque fournisseur qui agit comme sous-traitant.
2. Documenter les sous-traitants ultérieurs et les changements de liste.
3. Relever la région réellement choisie pour chaque base, stockage, service et sauvegarde.
4. Vérifier où sont traités les journaux, le support, les sauvegardes et la télémétrie.
5. Pour chaque transfert hors EEE, identifier le pays, le destinataire, le rôle, le mécanisme juridique (adéquation ou clauses contractuelles types, selon le cas) et l'évaluation du transfert lorsque nécessaire.
6. Vérifier les paramètres de conservation et de suppression des fournisseurs.
7. Mettre à jour ce tableau avant chaque nouvelle intégration.

Ne pas annoncer « toutes les données sont hébergées dans l'UE » tant que chaque région et flux n'a pas été vérifié.
