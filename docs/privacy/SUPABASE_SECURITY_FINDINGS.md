# Supabase — constats de sécurité vérifiés

> Relevé en lecture seule du projet Supabase « Stone » le 17 novembre 2026. À recontrôler après toute migration ou modification de configuration.

## Projet et hébergement

- Projet : `Stone`
- Région : `eu-west-1`
- État : `ACTIVE_HEALTHY`
- Base : PostgreSQL 17.6.1.166

## Row Level Security

Les 21 tables publiques inventoriées dans le projet ont RLS activé.

Les tables de contenu et de comptes sociaux ont des politiques propriétaires basées sur `auth.uid() = user_id`. Les politiques ont été vérifiées sur les tables de profil applicatif, de contenu, de notifications, de snapshots et de comptes connectés.

Les tables suivantes ont RLS activé sans politique et ne donnent pas de privilèges aux rôles `anon` / `authenticated` dans le projet observé ; elles sont utilisées par le backend avec `service_role` :
- `mfa_email_codes`
- `mfa_verified_sessions`
- `webauthn_challenges`
- `webauthn_credentials`
- `threads_accounts`

`mfa_email_settings` conserve une politique propriétaire pour le rôle `authenticated`. L'alerte Supabase « RLS Enabled No Policy » sur les tables réservées au backend est donc informative dans cette configuration, mais les privilèges doivent être recontrôlés après migration.

## Stockage Supabase

| Bucket | Public | Usage observé | Conséquence |
|---|---:|---|---|
| `avatars` | Oui | Avatars de profil | Tout détenteur de l'URL peut récupérer le fichier |
| `post-media` | Oui | Médias de publication | Tout détenteur de l'URL peut récupérer le fichier |
| `tiktok-media` | Non | Médias temporaires de publication TikTok | Bucket privé ; le backend expose une URL API temporaire pour permettre au réseau de récupérer le média |

Aucune politique `storage.objects` n'a été trouvée dans l'inspection SQL. Les buckets publics restent lisibles via leur URL publique ; les écritures du backend utilisent le rôle de service.

**Décision produit requise :** confirmer que les utilisateurs comprennent que les avatars et médias de publication sont accessibles par URL. Si des brouillons confidentiels doivent être pris en charge, concevoir une architecture de médias privés et des URL signées compatibles avec les délais de publication avant de changer les buckets.

## Alerte Supabase à corriger dans le Dashboard

L'advisor Supabase signale `auth_leaked_password_protection` : la protection contre les mots de passe compromis est désactivée.

Action à effectuer dans le Dashboard Supabase, section Auth / Security (libellé exact susceptible d'évoluer) : activer la vérification des mots de passe compromis. Cette option n'est pas modifiable par les outils de base de données utilisés pendant cet audit.

## Suppression des comptes

Aucune clé étrangère vers `auth.users` n'a été trouvée dans les schémas inspectés. La suppression d'un utilisateur doit donc supprimer explicitement les lignes de chaque table contenant `user_id` avant la suppression Auth. L'endpoint de suppression Stone contient maintenant cette liste explicite et retire les objets Storage sous les préfixes utilisateur.
