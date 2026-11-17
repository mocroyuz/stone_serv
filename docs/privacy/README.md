# Stone — dossier de conformité RGPD (interne)

> **Statut : dossier de travail incomplet — ne constitue pas une certification ni un avis juridique.**  
> Les éléments marqués « à confirmer » ne doivent pas être présentés aux utilisateurs comme des faits établis.

Ce dossier accompagne les dépôts `mocroyuz/Stone_prod` et `mocroyuz/stone_serv`.

## État des travaux techniques

- [x] Endpoint d'export JSON authentifié : `GET /api/user/export`.
- [x] Les tables absentes du schéma sont signalées dans le fichier au lieu de faire échouer silencieusement l'export.
- [ ] L'export reste partiel : médias binaires, factures Stripe et données détenues directement par les plateformes ne sont pas inclus. Les tables indisponibles sont indiquées.
- [x] Export limité aux enregistrements appartenant à l'utilisateur.
- [x] Exclusion des jetons OAuth, secrets, mots de passe, codes de récupération et données de sécurité sensibles.
- [x] Réponse d'export marquée `Cache-Control: no-store`.
- [x] Suppression de compte authentifiée avec confirmation, session récente, contrôle MFA si activé, annulation des abonnements actifs, révocation OAuth best-effort, suppression des lignes utilisateur, suppression des objets Storage préfixés et suppression du compte Auth.
- [ ] Vérifier en production les cas réels de chaque fournisseur, les erreurs partielles et les sauvegardes ; Pinterest/Threads peuvent demander une révocation manuelle.
- [x] Suppression des objets dans `avatars`, `post-media` et des futurs médias TikTok préfixés par utilisateur.
- [ ] Les anciens médias TikTok sans préfixe utilisateur expirent via le nettoyage TTL (seuil 2 h, balayage périodique) ; les sauvegardes et données chez les plateformes externes restent soumises à leurs propres règles.
- [x] Interface de consentement cookies : accepter, refuser, personnaliser et rouvrir les préférences.
- [ ] Blocage effectif des traceurs tiers : aucun traceur non essentiel n'a été identifié dans le dépôt, mais les scripts configurés hors dépôt restent à vérifier.
- [ ] Publication d'une notice de confidentialité finalisée.
- [ ] Publication d'une page Mentions légales complétée à partir de `LEGAL_NOTICE_DRAFT.md`.
- [ ] Vérification des contrats de sous-traitance, régions et transferts internationaux.
- [ ] Activer la protection Supabase contre les mots de passe compromis (alerte de sécurité du projet).
- [ ] Décider si les buckets publics `avatars` et `post-media` conviennent aux médias de brouillon ; la notice indique maintenant que les URLs sont accessibles publiquement.
- [ ] Validation du registre et des durées de conservation par le responsable du traitement.

## Informations indispensables à fournir par l'exploitant

1. Dénomination juridique exacte de l'exploitant et forme juridique.
2. Adresse postale professionnelle et pays d'établissement.
3. Adresse de contact relative aux données personnelles.
4. Existence ou non d'un DPO et ses coordonnées, si désigné.
5. Finalités et bases légales réellement retenues pour chaque traitement.
6. Régions d'hébergement réellement configurées chez chaque fournisseur.
7. Contrats/DPA, sous-traitants ultérieurs et garanties de transfert.
8. Durées de conservation validées, y compris sauvegardes et journaux.
9. Outils analytiques, pixels, SDK, cookies et scripts réellement déployés en production.
10. Entités et données accessibles via Stripe et les plateformes sociales.

## Règle de publication

Ne remplacez pas les champs `[À COMPLÉTER]` par des suppositions. Ne publiez pas la notice brouillon avant validation des informations et des pratiques réelles. Un dépôt Git ne permet pas, à lui seul, de vérifier les paramètres des comptes Vercel, Render, Supabase, Stripe ou des plateformes sociales.
