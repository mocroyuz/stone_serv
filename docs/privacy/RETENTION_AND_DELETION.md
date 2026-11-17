# Politique de conservation et d'effacement — Stone

> **État : à approuver et à mettre en œuvre.** Les durées proposées ci-dessous ne sont pas des durées actuellement garanties par le code. Elles doivent être validées par le responsable du traitement selon les besoins, les obligations comptables, les contrats et les règles des fournisseurs.

| Catégorie | Règle cible | Statut actuel / vérification requise |
|---|---|---|
| Compte actif | Conservation tant que nécessaire à la fourniture du service | Pas de politique complète identifiée |
| Compte supprimé | Suppression des lignes utilisateur, objets Storage préfixés et compte Auth ; exceptions légales isolées | Endpoint `DELETE /api/user/account` implémenté ; tests de suppression en production à réaliser |
| Jetons OAuth | Révocation distante lorsque possible puis suppression locale des lignes contenant les jetons | Révocation best-effort ; Pinterest/Threads peuvent nécessiter une révocation manuelle |
| Publications et médias | Suppression ou anonymisation selon choix de l'utilisateur et dépendances des publications | Vérifier toutes les tables, buckets et copies |
| Avatar | Suppression des objets du préfixe utilisateur dans `avatars` | Pris en charge par l'endpoint de suppression du compte ; vérifier les objets orphelins historiques |
| Logs API / sécurité | Durée courte, proportionnée et documentée ; accès restreint | Inventaire et TTL à vérifier ; les journaux Render nécessitent une vérification séparée |
| Exports de données | Fichier temporaire, accès authentifié, expiration automatique et suppression après téléchargement/expiration | Export actuel renvoyé en réponse API, aucun fichier serveur conservé |
| Données de facturation | Conservation selon obligations fiscales/comptables applicables | Vérifier Stripe et la juridiction de l'exploitant |
| Sauvegardes | Expiration documentée ; données supprimées ne doivent pas être restaurées indéfiniment | Paramètres de sauvegarde Supabase/Render non vérifiés ; suppression des données actives ne prouve pas l'effacement des sauvegardes |
| Demandes RGPD | Conservation limitée de la demande et de la preuve de réponse | Procédure et durée à définir |

## Plan d'effacement à mettre en œuvre

1. Authentifier le demandeur et vérifier son identité de façon proportionnée.
2. Bloquer les nouvelles publications et tâches planifiées liées au compte.
3. Révoquer les jetons OAuth auprès des plateformes lorsque leur API le permet.
4. Supprimer les enregistrements de connexion et les jetons chiffrés.
5. Supprimer les publications, tags, groupes, réponses enregistrées, notifications et autres données utilisateur.
6. Supprimer les objets et dérivés dans chaque bucket Storage, y compris miniatures et fichiers temporaires.
7. Supprimer les données de compte dans Supabase Auth et invalider les sessions.
8. Traiter Stripe selon les obligations de conservation et les contrats ; ne pas supprimer des factures qui doivent légalement être conservées.
9. Propager la suppression aux sous-traitants lorsque requis.
10. Documenter les exceptions légales, les sauvegardes et la date d'effacement final.

**Important :** l'endpoint supprime les tables utilisateur connues, les objets Storage sous le préfixe utilisateur et le compte Auth. Les autorisations Pinterest/Threads peuvent rester actives jusqu'à révocation manuelle. Les anciennes images TikTok sans préfixe expirent via le balayage TTL. Les contenus publiés sur les réseaux sociaux, les fichiers sources externes, les sauvegardes et les factures Stripe ne sont pas effacés par cet endpoint.
