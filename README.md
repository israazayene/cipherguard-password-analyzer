# 🔐 CipherGuard — Password Strength Analyzer

<div align="center">

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-00e5ff?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-00e676?style=for-the-badge)

**Application web de cybersécurité pour analyser et générer des mots de passe robustes.**  
Entièrement construite en HTML / CSS / JavaScript vanilla — sans dépendance externe.

[ Démo en ligne](#) · [ Signaler un bug](issues) · [ Proposer une fonctionnalité](issues)

</div>

---

##  Aperçu

> Interface dark mode, style cyberpunk, responsive desktop + mobile.

---

## ✨ Fonctionnalités

### 🔍 Analyseur de mot de passe
- **Score en temps réel** (0 – 100) calculé à chaque frappe
- **Barre de progression animée** avec 3 niveaux de force : Faible / Moyen / Fort
- **Vérification de 6 critères** :
  - Longueur ≥ 8 caractères
  - Lettres majuscules (A–Z)
  - Lettres minuscules (a–z)
  - Chiffres (0–9)
  - Caractères spéciaux (!@#$…)
  - Longueur bonus ≥ 12 caractères
- **Détection des mauvaises pratiques** : répétitions (`aaa`), séquences (`123`, `qwerty`…)
- **Conseils intelligents et personnalisés** selon les critères manquants
- **Bouton afficher / masquer** le mot de passe

### 🎲 Générateur de mot de passe sécurisé
- **Longueur personnalisable** de 8 à 64 caractères via un slider intuitif
- **Options configurables** : majuscules, minuscules, chiffres, caractères spéciaux
- **Mode "sans ambigus"** : exclut les caractères visuellement confusants (`0`, `O`, `l`, `I`…)
- **Cryptographiquement sûr** : utilise l'API Web Crypto (`window.crypto.getRandomValues`)
- **Calcul de l'entropie** en bits avec interprétation (Faible → Excellente)
- **Copie en un clic** dans le presse-papier
- **Analyse directe** : envoie le mot de passe généré vers l'analyseur en un clic

---

##  Technologies utilisées

| Technologie | Utilisation |
|-------------|-------------|
| **HTML5** | Structure sémantique, accessibilité (ARIA) |
| **CSS3** | Variables CSS, animations `@keyframes`, Flexbox / Grid, Responsive Design |
| **JavaScript ES6+** | Modules logiques, Web Crypto API, Clipboard API, DOM manipulation |

> **Aucun framework, aucune librairie externe.** Code 100 % vanilla, zéro dépendance.

---

##  Structure du projet

```
password-strength-checker/
├── index.html      # Structure HTML sémantique + accessibilité
├── style.css       # Thème dark cybersécurité, animations, responsive
├── script.js       # Logique analyseur + générateur cryptographique
└── README.md       # Documentation complète
```

---

##  Installation & Utilisation

1. **Cloner le dépôt**
   ```bash
   git clone https://github.com/votre-username/password-strength-checker.git
   cd password-strength-checker
   ```

2. **Lancer l'application**  
   Ouvrir `index.html` directement dans votre navigateur — aucun serveur requis.

   Ou avec un serveur local :
   ```bash
   # Python
   python -m http.server 8000

   # Node.js (npx)
   npx serve .
   ```

3. **Accéder à l'app** : [http://localhost:8000](http://localhost:8000)

---

##  Sécurité & Algorithme

### Calcul du score
Le score (0–100) est calculé selon les critères suivants :

| Critère | Points |
|---------|--------|
| Longueur ≥ 8 | +20 |
| Présence de majuscules | +15 |
| Présence de minuscules | +15 |
| Présence de chiffres | +15 |
| Présence de caractères spéciaux | +20 |
| Longueur ≥ 12 (bonus) | +15 |
| Longueur ≥ 16 (bonus) | +5 |
| Longueur ≥ 20 (bonus) | +5 |
| Caractères répétés (aaa, 111…) | −10 |
| Séquences communes (abc, 123…) | −10 |

### Génération cryptographiquement sûre
Le générateur utilise `window.crypto.getRandomValues()` (API Web Crypto) au lieu de `Math.random()` pour garantir une entropie maximale et résister aux attaques par prédiction.

**Calcul de l'entropie :** `E = log₂(N^L)` où N = taille de l'alphabet, L = longueur.

---

##  Idées d'améliorations futures

- [ ] **Détection de mots de passe compromis** via l'API [Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [ ] **Estimation du temps de crack** (attaque brute force)
- [ ] **Thème clair** en option
- [ ] **Export** de la liste de mots de passe générés en `.txt` chiffré
- [ ] **Mode passphrase** (ex : `cheval-batterie-agrafes`)
- [ ] **Détection de langue** pour les mots courants (dictionnaire)
- [ ] **Extension navigateur** Chrome / Firefox
- [ ] **Tests unitaires** avec Jest
- [ ] **PWA** (Progressive Web App) avec installation sur mobile
- [ ] **Internationalisation** (EN / FR / AR)

---

##  Licence

Distribué sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus d'informations.

---

## 👤 Auteur

**[Votre Nom]**  
📧 [votre.email@exemple.com]  
🔗 [LinkedIn](https://linkedin.com/in/votre-profil)  
🐙 [GitHub](https://github.com/votre-username)

---

<div align="center">
  Fait avec ❤️ et beaucoup de café · Projet personnel étudiant en informatique
</div>
