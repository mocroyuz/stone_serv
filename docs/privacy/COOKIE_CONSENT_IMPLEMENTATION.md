# Cookies et traceurs — état et exigences d'implémentation

## Résultat de la revue du dépôt

La recherche du code frontend n'a pas identifié d'intégration explicite connue de Google Analytics, Meta Pixel, PostHog ou d'un gestionnaire de tags. Cette observation ne permet pas d'exclure :
- des scripts injectés dans Vercel, le CDN ou une extension ;
- des scripts chargés dynamiquement par une dépendance ;
- des cookies déposés par des fournisseurs tiers ;
- des traceurs présents dans des pages externes ou outils de support.

Un contrôle navigateur en production reste nécessaire.

## État

- Gestionnaire de consentement complet : **non implémenté**.
- Blocage avant consentement : **non démontré**.
- Refus aussi simple que l'acceptation : **non démontré**.
- Retrait du consentement depuis les paramètres : **non implémenté**.
- Journal de preuve et version du texte de consentement : **non implémentés**.

## Exigences avant activation de traceurs

1. Inventorier chaque cookie, stockage local, pixel, SDK et requête réseau.
2. Classer chaque élément : strictement nécessaire, mesure d'audience exemptée si les conditions sont démontrées, ou soumis au consentement.
3. Ne pas charger les scripts non essentiels avant consentement.
4. Présenter des choix « Tout accepter », « Tout refuser » et « Personnaliser » avec une facilité équivalente.
5. Désactiver les catégories facultatives par défaut.
6. Permettre le retrait à tout moment depuis un lien « Gérer les cookies » accessible sur toutes les pages.
7. Enregistrer la version de la notice, la date et le choix sans conserver de données excessives.
8. Respecter le choix sur tous les domaines et sous-domaines concernés, selon l'architecture.
9. Tester le refus, l'acceptation, la personnalisation et le retrait dans un navigateur propre.

Ne pas afficher un bandeau donnant l'impression que des traceurs sont contrôlés si les scripts correspondants ne sont pas effectivement conditionnés à ce choix.
