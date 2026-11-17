# Politique de conservation et d'effacement — Stone

> **État : à approuver et à mettre en œuvre.** Les durées proposées ci-dessous ne sont pas des durées actuellement garanties par le code. Elles doivent être validées par le responsable du traitement selon les besoins, les obligations comptables, les contrats et les règles des fournisseurs.

| Catégorie | Règle cible | Statut actuel / vérification requise |
|---|---|---|
| Compte actif | Conservation tant que nécessaire à la fourniture du service | Pas de politique complète identifiée |
| Compte supprimé | Suppression ou anonymisation des données actives dans un délai documenté ; exceptions légales isolées | Suppression complète non implémentée |
| Jetons OAuth | Suppression immédiate à la déconnexion ou à la suppression du compte, après révocation lorsque possible | Jetons chiffrés en base ; cycle de suppression à vérifier |
| Publications et médias | Suppression ou anonymisation selon choix de l'utilisateur et dépendances des publications | Vérifier toutes les tables, buckets et copies |
| Avatar | Suppression de l'objet Storage et de la référence de profil | Endpoint de suppression d'avatar existant ; vérifier les objets orphelins |
| Logs API / sécurité | Durée courte, proportionnée et documentée ; accès restreint | Inventaire et TTL à vérifier |
| Exports de données | Fichier temporaire, accès authentifié, expiration automatique et suppression après téléchargement/expiration | Export actuel renvoyé en réponse API, aucun fichier serveur conservé |
| Données de facturation | Conservation selon obligations fiscales/comptables applicables | Vérifier Stripe et la juridiction de l'exploitant |
| Sauvegardes | Expiration documentée ; données supprimées ne doivent pas être restaurées indéfiniment | Paramètres fournisseur à vérifier |
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

**Important :** la suppression Auth seule ne prouve pas la suppression des fichiers Storage, des données chez les réseaux sociaux, des sauvegardes ni des données conservées pour obligations légales. Le code de suppression ne doit être activé qu'après inventaire des clés étrangères, buckets, tâches asynchrones et flux OAuth.
