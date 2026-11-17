# Registre des activités de traitement — Stone

> **Brouillon interne.** Le responsable du traitement doit confirmer chaque ligne, les bases légales, les destinataires et les durées. Les bases légales proposées ci-dessous sont des pistes à valider, pas des décisions juridiques déjà prises.

| Traitement | Personnes concernées | Données potentiellement traitées | Finalité | Base légale à valider | Destinataires / sous-traitants | Conservation |
|---|---|---|---|---|---|---|
| Création et gestion du compte | Utilisateurs | Email, identifiant, nom, prénom, profil, date de création, métadonnées de compte | Fournir le service, authentifier et gérer le compte | Contrat ; obligations légales pour certains éléments | Supabase, Render, Vercel | Durée du compte puis suppression/archivage justifié |
| Authentification et sécurité | Utilisateurs | Journaux d'authentification, IP, informations de session, MFA, passkeys | Sécuriser les accès, prévenir les abus | Intérêt légitime à documenter ; obligations applicables | Supabase, Render | Durée courte à définir selon nécessité et sécurité |
| Publications et calendrier | Utilisateurs et personnes mentionnées dans les contenus | Textes, médias, dates, statuts, identifiants de comptes sociaux | Programmer et publier les contenus demandés | Contrat ; consentement/autorisation de connexion selon les flux | Supabase, Render, plateformes sociales | Durée du compte et règles de suppression à définir |
| Connexions aux réseaux sociaux | Utilisateurs, administrateurs de pages/comptes | Identifiants de comptes, scopes, jetons OAuth chiffrés, métadonnées de profil | Connecter les comptes et exécuter les actions autorisées | Contrat et autorisation donnée à la plateforme ; base à documenter | Render, Supabase, Meta, Google, TikTok, Pinterest, Threads | Révocation/déconnexion et suppression à définir |
| Import et stockage de médias | Utilisateurs et personnes figurant dans les médias | Fichiers, noms, métadonnées, URL, miniatures | Importer, stocker et publier les médias | Contrat ; droits et autorisations du déposant à traiter | Supabase Storage, Google Drive/Photos, Dropbox, Canva | Durée du compte et politique de suppression à définir |
| Paiements et abonnements | Clients / utilisateurs payeurs | Identifiants Stripe, statut d'abonnement, factures, historique de paiement et informations nécessaires | Facturation, paiement, gestion d'abonnement | Contrat et obligations légales/comptables | Stripe, Stone, prestataires d'hébergement | Durées légales comptables à confirmer selon juridiction |
| Support et demandes relatives aux droits | Utilisateurs | Coordonnées, contenu de la demande, vérification d'identité, historique de réponse | Répondre au support et exercer les droits RGPD | Obligation légale / intérêt légitime à documenter | Outil de support à identifier, email, hébergeurs | Durée de traitement et preuve de réponse à définir |
| Mesure d'audience / marketing | Visiteurs et utilisateurs | À déterminer selon les traceurs réellement installés | Mesure d'audience ou publicité, si activées | Consentement si requis ; exemptions éventuelles à démontrer | Aucun outil confirmé par la revue du code ; vérifier les scripts déployés | À définir avant activation |

## Éléments à compléter pour chaque activité

- Responsable du traitement et coordonnées.
- Catégories de personnes et de données exactes.
- Source des données (utilisateur, réseau social, fournisseur).
- Base légale et justification documentée.
- Destinataires, sous-traitants et accès internes.
- Transferts hors EEE et mécanisme applicable.
- Durée ou critères de conservation.
- Mesures de sécurité et habilitations.
- Procédure d'exercice des droits.
- Analyse de nécessité d'une AIPD (DPIA), notamment si le traitement évolue vers un suivi systématique ou présente un risque élevé.

Ne pas considérer ce tableau comme exhaustif avant inventaire des environnements de production et des données réellement stockées.
