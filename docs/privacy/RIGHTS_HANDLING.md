# Procédure de traitement des demandes RGPD — Stone

## Canaux de réception

- Adresse dédiée : **[À COMPLÉTER par l'exploitant]**
- Formulaire de contact : **[URL À CONFIRMER]**
- Adresse postale : **[À COMPLÉTER]**

Ne pas publier d'adresse fictive ni utiliser `privacy@example.com`.

## Procédure

- Portabilité : l'utilisateur peut télécharger un export JSON depuis Settings > Danger Zone (`GET /api/user/export`). L'export est authentifié, sans cache, exclut les secrets et signale les tables absentes. Il n'inclut pas les fichiers binaires, les données détenues directement par les plateformes externes ni les factures Stripe.
- Effacement du compte : l'utilisateur peut lancer la suppression depuis Settings > Danger Zone (`DELETE /api/user/account`). L'endpoint exige une authentification récente, une confirmation explicite et le niveau MFA requis si le compte l'utilise. Il annule les abonnements Stripe actifs, tente la révocation des intégrations, supprime les lignes des tables utilisateur connues, les objets Storage sous le préfixe utilisateur et le compte Auth.
- L'endpoint renvoie les révocations qui nécessitent une action manuelle. Pinterest et Threads peuvent nécessiter que l'utilisateur retire Stone depuis les paramètres de la plateforme. Les factures et données de facturation peuvent être conservées lorsque la loi l'exige.

1. Enregistrer la date de réception, le droit exercé et le canal utilisé.
2. Vérifier que la demande concerne des données traitées par Stone.
3. Vérifier l'identité avec des moyens proportionnés. Ne pas demander systématiquement une copie de pièce d'identité si l'identité peut être confirmée autrement.
4. Identifier les systèmes concernés : Supabase Auth/DB/Storage, backend Render, frontend/Vercel, Stripe, réseaux sociaux, support et sauvegardes.
5. Faire intervenir les sous-traitants lorsque nécessaire.
6. Répondre dans le délai RGPD applicable (en principe un mois, avec prolongation possible dans les conditions prévues par le règlement).
7. Si la demande est refusée ou limitée, expliquer les motifs et les voies de recours.
8. Conserver une preuve minimale de la demande et de la réponse selon une durée définie.
9. Ne jamais transmettre les jetons OAuth, secrets, mots de passe, codes MFA ou données de sécurité dans un export.

## Droits à prendre en charge

L'export et l'effacement du compte disposent maintenant d'un parcours technique dans l'application. Les autres droits (rectification, limitation, opposition, retrait du consentement) nécessitent encore un canal de contact privacy fonctionnel et un traitement opérationnel documenté.

- Accès : fournir une copie intelligible des données et les informations requises.
- Rectification : corriger les données inexactes.
- Effacement : supprimer les données sans délai indu, sous réserve des exceptions légales.
- Limitation : marquer et suspendre certains traitements lorsque les conditions sont réunies.
- Portabilité : fournir les données concernées dans un format structuré, couramment utilisé et lisible par machine lorsque le droit s'applique.
- Opposition : examiner l'opposition selon la base légale et la finalité.
- Retrait du consentement : aussi simple que le consentement, sans effet rétroactif sur le traitement antérieur licite.
- Réclamation : informer de la possibilité de saisir l'autorité de contrôle compétente.

## Suivi interne minimal

| Champ | Valeur |
|---|---|
| Référence de demande | À générer |
| Date de réception | À renseigner |
| Identité vérifiée | Oui / non / non nécessaire |
| Droit exercé | À renseigner |
| Systèmes consultés | À renseigner |
| Sous-traitants sollicités | À renseigner |
| Date de réponse | À renseigner |
| Résultat / justification | À renseigner |
| Date d'effacement final si applicable | À renseigner |
