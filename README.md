# CipherGuard — Password Strength Analyzer

Une application web qui analyse la force de tes mots de passe et en génère des nouveaux sécurisés.
Construit avec HTML, CSS et JavaScript pur — sans aucune librairie externe.

---

##  Démo

> Télécharge les fichiers et ouvre `index.html` dans ton navigateur. C'est tout !

---

## Ce que fait l'application

**Analyser un mot de passe**
- Affiche un score de force de 0 à 100
- Montre une barre de progression colorée (rouge → orange → vert)
- Vérifie 6 critères : longueur, majuscules, minuscules, chiffres, caractères spéciaux, longueur bonus
- Donne des conseils personnalisés pour améliorer le mot de passe
- Bouton pour afficher ou masquer le mot de passe

**Générer un mot de passe**
- Choisis la longueur (8 à 64 caractères) avec un slider
- Coche les types de caractères que tu veux inclure
- Option pour exclure les caractères visuellement confusants (0, O, l, I…)
- Copie en un clic dans le presse-papier
- Envoie directement le mot de passe généré vers l'analyseur

---

##  Structure des fichiers

```
password-strength-checker/
├── index.html   → La page web (structure)
├── style.css    → Le design (thème dark cybersécurité)
├── script.js    → La logique (analyse + génération)
└── README.md    → Ce fichier
```

---

##  Installation

1. Clone le projet :
```bash
git clone https://github.com/ton-username/password-strength-checker.git
```

2. Ouvre le fichier `index.html` dans ton navigateur.

Aucune installation, aucun serveur, aucune dépendance requise.

---

##  Technologies utilisées

- **HTML5** — structure de la page
- **CSS3** — design, animations, responsive mobile
- **JavaScript (ES6+)** — logique de l'application, Web Crypto API pour la génération sécurisée

---

##  Améliorations possibles

- Vérifier si le mot de passe a déjà été piraté (API Have I Been Pwned)
- Afficher le temps estimé pour craquer le mot de passe
- Ajouter un thème clair
- Générer des passphrases (ex : `cheval-batterie-agrafes`)
- Transformer en extension navigateur

---
> Projet personnel réalisé dans le cadre de ma formation en informatique.
