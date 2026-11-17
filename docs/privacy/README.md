# Stone — dossier de conformité RGPD (interne)

> **Statut : dossier de travail incomplet — ne constitue pas une certification ni un avis juridique.**  
> Les éléments marqués « à confirmer » ne doivent pas être présentés aux utilisateurs comme des faits établis.

Ce dossier accompagne les dépôts `mocroyuz/Stone_prod` et `mocroyuz/stone_serv`.

## État des travaux techniques

- [x] Endpoint d'export JSON authentifié : `GET /api/user/export`.
- [x] Export limité aux enregistrements appartenant à l'utilisateur.
- [x] Exclusion des jetons OAuth, secrets, mots de passe, codes de récupération et données de sécurité sensibles.
- [x] Réponse d'export marquée `Cache-Control: no-store`.
- [ ] Suppression complète du compte : non implémentée. Ne pas annoncer cette fonction comme disponible.
- [ ] Suppression vérifiée des objets Storage, des données liées, des sauvegardes et révocation des autorisations tierces.
- [ ] Gestionnaire de consentement opérationnel et blocage effectif des traceurs avant consentement.
- [ ] Publication d'une notice de confidentialité finalisée.
- [ ] Vérification des contrats de sous-traitance, régions et transferts internationaux.
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
