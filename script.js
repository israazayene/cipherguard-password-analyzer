/**
 * ═══════════════════════════════════════════════════════════════
 * CipherGuard — script.js
 * Analyseur de force de mot de passe + Générateur sécurisé
 *
 * Auteur  : [Votre Nom]
 * Version : 1.0.0
 *
 * Architecture :
 *  1. Sélecteurs DOM
 *  2. Constantes & données
 *  3. Utilitaires
 *  4. Module Analyseur (analyzePassword)
 *  5. Module Générateur (generatePassword)
 *  6. Mise à jour de l'interface (updateUI)
 *  7. Gestionnaires d'événements
 *  8. Initialisation
 * ════════════════════════════════════════════════════════════════
 */

'use strict';

/* ────────────────────────────────────────────────────────────────
   1. SÉLECTEURS DOM
   — On centralise tous les éléments ici pour éviter les
     querySelector() dispersés partout dans le code.
────────────────────────────────────────────────────────────────── */
const DOM = {
  // Analyseur
  passwordInput:    document.getElementById('password-input'),
  toggleBtn:        document.getElementById('toggle-btn'),
  strengthLabel:    document.getElementById('strength-label'),
  strengthScore:    document.getElementById('strength-score'),
  progressBar:      document.getElementById('progress-bar'),
  progressTrack:    document.querySelector('.progress-track'),
  tipsList:         document.getElementById('tips-list'),

  // Critères
  critLength:       document.getElementById('crit-length'),
  critUpper:        document.getElementById('crit-upper'),
  critLower:        document.getElementById('crit-lower'),
  critNumber:       document.getElementById('crit-number'),
  critSpecial:      document.getElementById('crit-special'),
  critLong:         document.getElementById('crit-long'),

  // Générateur
  genLength:        document.getElementById('gen-length'),
  genLengthDisplay: document.getElementById('gen-length-display'),
  genUpper:         document.getElementById('gen-upper'),
  genLower:         document.getElementById('gen-lower'),
  genNumbers:       document.getElementById('gen-numbers'),
  genSpecial:       document.getElementById('gen-special'),
  genAmbiguous:     document.getElementById('gen-ambiguous'),
  generateBtn:      document.getElementById('generate-btn'),
  generatedPassword:document.getElementById('generated-password'),
  copyBtn:          document.getElementById('copy-btn'),
  entropyInfo:      document.getElementById('entropy-info'),
  analyzeGenBtn:    document.getElementById('analyze-generated-btn'),
};

/* ────────────────────────────────────────────────────────────────
   2. CONSTANTES & DONNÉES
────────────────────────────────────────────────────────────────── */

/** Seuils de score pour déterminer la force */
const STRENGTH = {
  WEAK:   { max: 39,  label: 'Faible',  cls: 'weak'   },
  MEDIUM: { max: 69,  label: 'Moyen',   cls: 'medium'  },
  STRONG: { max: 100, label: 'Fort',    cls: 'strong'  },
};

/**
 * Jeux de caractères pour le générateur.
 * Chaque jeu exclut ses variantes « ambiguës » dans charsetClean.
 */
const CHARSETS = {
  upper:   { full: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', clean: 'ABCDEFGHJKLMNPQRSTUVWXYZ' },
  lower:   { full: 'abcdefghijklmnopqrstuvwxyz', clean: 'abcdefghjkmnpqrstuvwxyz' },
  numbers: { full: '0123456789',                  clean: '23456789' },
  special: { full: '!@#$%^&*()_+-=[]{}|;:,.<>?', clean: '!@#$%^&*_+-=[]{}|;:,.<>?' },
};

/**
 * Bibliothèque de conseils de sécurité.
 * Chaque conseil est associé à une condition : si la condition
 * est vraie (critère NON satisfait), le conseil s'affiche.
 * @typedef {{ condition: (r: AnalysisResult) => boolean, text: string }} Tip
 */
const TIPS = [
  { condition: r => !r.hasLength,   text: 'Utilisez au moins 8 caractères.' },
  { condition: r => !r.hasUpper,    text: 'Ajoutez des lettres MAJUSCULES (A–Z).' },
  { condition: r => !r.hasLower,    text: 'Ajoutez des lettres minuscules (a–z).' },
  { condition: r => !r.hasNumber,   text: 'Incluez des chiffres (0–9).' },
  { condition: r => !r.hasSpecial,  text: 'Ajoutez des caractères spéciaux (!@#$…).' },
  { condition: r => !r.hasLongLen,  text: 'Visez 12+ caractères pour une sécurité maximale.' },
  { condition: r => r.score >= 70,  text: '✓ Excellente longueur ! Continuez ainsi.' },
  { condition: r => r.hasRepeats,   text: 'Évitez les caractères répétés (aaa, 111…).' },
  { condition: r => r.hasSequence,  text: 'Évitez les séquences (abc, 123, qwerty…).' },
];

/** Séquences communes à détecter (attaques par dictionnaire) */
const COMMON_SEQUENCES = ['abc','bcd','cde','def','efg','fgh','ghi','hij','ijk',
  'jkl','klm','lmn','mno','nop','opq','pqr','qrs','rst','stu','tuv','uvw',
  'vwx','wxy','xyz','012','123','234','345','456','567','678','789',
  'qwe','wer','ert','rty','tyu','yui','uio','iop','asd','sdf','dfg',
  'fgh','ghj','hjk','jkl','zxc','xcv','cvb','vbn','bnm'];

/* ────────────────────────────────────────────────────────────────
   3. UTILITAIRES
────────────────────────────────────────────────────────────────── */

/**
 * Détecte si un mot de passe contient des répétitions (≥3 chars identiques consécutifs).
 * @param {string} password
 * @returns {boolean}
 */
function hasRepeatedChars(password) {
  return /(.)\1{2,}/.test(password);
}

/**
 * Détecte si un mot de passe contient une séquence commune.
 * @param {string} password
 * @returns {boolean}
 */
function hasCommonSequence(password) {
  const lower = password.toLowerCase();
  return COMMON_SEQUENCES.some(seq => lower.includes(seq));
}

/**
 * Calcule l'entropie d'un mot de passe généré en bits.
 * Formule : log2(taille_alphabet ^ longueur)
 * @param {number} alphabetSize — Taille de l'alphabet utilisé
 * @param {number} length       — Longueur du mot de passe
 * @returns {number} entropie en bits (arrondie)
 */
function calcEntropy(alphabetSize, length) {
  if (alphabetSize === 0 || length === 0) return 0;
  return Math.round(Math.log2(Math.pow(alphabetSize, length)));
}

/**
 * Interprète l'entropie en niveau de sécurité.
 * @param {number} bits
 * @returns {string}
 */
function entropyLabel(bits) {
  if (bits < 40)  return 'Très faible';
  if (bits < 60)  return 'Faible';
  if (bits < 80)  return 'Acceptable';
  if (bits < 100) return 'Bonne';
  if (bits < 128) return 'Très bonne';
  return 'Excellente';
}

/**
 * Génère un nombre aléatoire cryptographiquement sûr dans [0, max[.
 * Utilise l'API Web Crypto disponible dans tous les navigateurs modernes.
 * @param {number} max
 * @returns {number}
 */
function secureRandom(max) {
  const arr = new Uint32Array(1);
  window.crypto.getRandomValues(arr);
  // On divise par 2^32 pour obtenir un float uniforme [0, 1[
  return Math.floor((arr[0] / 0x100000000) * max);
}

/**
 * Mélange un tableau en place (algorithme Fisher-Yates).
 * Utilisé pour randomiser l'ordre des caractères générés.
 * @param {Array} arr
 * @returns {Array}
 */
function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandom(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/* ────────────────────────────────────────────────────────────────
   4. MODULE ANALYSEUR
────────────────────────────────────────────────────────────────── */

/**
 * @typedef {Object} AnalysisResult
 * @property {boolean} hasLength   — Longueur ≥ 8
 * @property {boolean} hasUpper    — Contient au moins 1 majuscule
 * @property {boolean} hasLower    — Contient au moins 1 minuscule
 * @property {boolean} hasNumber   — Contient au moins 1 chiffre
 * @property {boolean} hasSpecial  — Contient au moins 1 caractère spécial
 * @property {boolean} hasLongLen  — Longueur ≥ 12
 * @property {boolean} hasRepeats  — Contient des répétitions
 * @property {boolean} hasSequence — Contient une séquence commune
 * @property {number}  score       — Score de 0 à 100
 * @property {string}  strength    — 'weak' | 'medium' | 'strong'
 * @property {string}  label       — Libellé affiché
 * @property {Tip[]}   tips        — Liste des conseils pertinents
 */

/**
 * Analyse un mot de passe et retourne un objet AnalysisResult.
 * @param {string} password
 * @returns {AnalysisResult}
 */
function analyzePassword(password) {
  /* — Vérification des critères — */
  const hasLength   = password.length >= 8;
  const hasUpper    = /[A-Z]/.test(password);
  const hasLower    = /[a-z]/.test(password);
  const hasNumber   = /[0-9]/.test(password);
  const hasSpecial  = /[^A-Za-z0-9]/.test(password);
  const hasLongLen  = password.length >= 12;
  const hasRepeats  = hasRepeatedChars(password);
  const hasSequence = hasCommonSequence(password);

  /* — Calcul du score sur 100 — */
  let score = 0;

  // Points positifs
  if (hasLength)  score += 20;  // Base obligatoire
  if (hasUpper)   score += 15;  // Diversité de casse
  if (hasLower)   score += 15;  // Diversité de casse
  if (hasNumber)  score += 15;  // Diversité de type
  if (hasSpecial) score += 20;  // Espace de recherche beaucoup plus grand
  if (hasLongLen) score += 15;  // Longueur = facteur le plus important

  // Pénalités
  if (hasRepeats)  score = Math.max(0, score - 10);
  if (hasSequence) score = Math.max(0, score - 10);

  // Bonus progressif selon la longueur réelle
  if (password.length >= 16) score = Math.min(100, score + 5);
  if (password.length >= 20) score = Math.min(100, score + 5);

  /* — Détermination du niveau de force — */
  let strengthInfo;
  if      (score <= STRENGTH.WEAK.max)   strengthInfo = STRENGTH.WEAK;
  else if (score <= STRENGTH.MEDIUM.max) strengthInfo = STRENGTH.MEDIUM;
  else                                   strengthInfo = STRENGTH.STRONG;

  /* — Construction de la liste de conseils — */
  const result = { hasLength, hasUpper, hasLower, hasNumber, hasSpecial,
                   hasLongLen, hasRepeats, hasSequence, score,
                   strength: strengthInfo.cls, label: strengthInfo.label, tips: [] };

  result.tips = TIPS.filter(tip => tip.condition(result)).map(tip => tip.text);

  // Si tout est parfait, message d'encouragement
  if (result.tips.length === 0) {
    result.tips = ['Mot de passe excellent ! Pensez à l\'enregistrer dans un gestionnaire de mots de passe sécurisé.'];
  }

  return result;
}

/* ────────────────────────────────────────────────────────────────
   5. MODULE GÉNÉRATEUR
────────────────────────────────────────────────────────────────── */

/**
 * Génère un mot de passe cryptographiquement sûr selon les options choisies.
 * Garantit qu'au moins un caractère de chaque type activé est présent.
 *
 * @param {Object} options
 * @param {number}  options.length     — Longueur souhaitée
 * @param {boolean} options.upper      — Inclure les majuscules
 * @param {boolean} options.lower      — Inclure les minuscules
 * @param {boolean} options.numbers    — Inclure les chiffres
 * @param {boolean} options.special    — Inclure les caractères spéciaux
 * @param {boolean} options.noAmbiguous — Exclure les caractères ambigus
 * @returns {{ password: string, alphabetSize: number }}
 */
function generatePassword(options) {
  const { length, upper, lower, numbers, special, noAmbiguous } = options;

  // Construire l'alphabet complet selon les options
  const key = noAmbiguous ? 'clean' : 'full';
  let alphabet = '';
  const guaranteedChars = [];  // Au moins un char de chaque type activé

  if (upper) {
    alphabet += CHARSETS.upper[key];
    // Garantir au moins une majuscule
    guaranteedChars.push(CHARSETS.upper[key][secureRandom(CHARSETS.upper[key].length)]);
  }
  if (lower) {
    alphabet += CHARSETS.lower[key];
    guaranteedChars.push(CHARSETS.lower[key][secureRandom(CHARSETS.lower[key].length)]);
  }
  if (numbers) {
    alphabet += CHARSETS.numbers[key];
    guaranteedChars.push(CHARSETS.numbers[key][secureRandom(CHARSETS.numbers[key].length)]);
  }
  if (special) {
    alphabet += CHARSETS.special[key];
    guaranteedChars.push(CHARSETS.special[key][secureRandom(CHARSETS.special[key].length)]);
  }

  // Aucune option sélectionnée ? On force les minuscules
  if (alphabet === '') {
    alphabet = CHARSETS.lower.full;
    guaranteedChars.push(CHARSETS.lower.full[secureRandom(CHARSETS.lower.full.length)]);
  }

  // Compléter avec des caractères aléatoires jusqu'à la longueur souhaitée
  const remainingLength = Math.max(0, length - guaranteedChars.length);
  const randomChars = Array.from({ length: remainingLength },
    () => alphabet[secureRandom(alphabet.length)]
  );

  // Mélanger pour éviter que les caractères garantis soient toujours en début
  const allChars = shuffleArray([...guaranteedChars, ...randomChars]);
  const password = allChars.join('');

  return { password, alphabetSize: alphabet.length };
}

/* ────────────────────────────────────────────────────────────────
   6. MISE À JOUR DE L'INTERFACE
────────────────────────────────────────────────────────────────── */

/**
 * Applique les résultats d'analyse à l'interface.
 * @param {AnalysisResult} result
 */
function updateUI(result) {
  const { score, strength, label,
          hasLength, hasUpper, hasLower, hasNumber, hasSpecial, hasLongLen,
          tips } = result;

  /* — Barre de progression — */
  DOM.progressBar.style.width = `${score}%`;

  // Retirer les anciennes classes de couleur
  DOM.progressBar.classList.remove('weak', 'medium', 'strong');
  DOM.progressBar.classList.add(strength);

  // Accessibilité : mettre à jour aria-valuenow
  DOM.progressTrack.setAttribute('aria-valuenow', score);

  /* — Label et score — */
  DOM.strengthLabel.textContent = label;
  DOM.strengthLabel.className = `strength-label ${strength}`;

  DOM.strengthScore.textContent = `${score} / 100`;
  DOM.strengthScore.className = `strength-score ${strength}`;

  /* — Critères — */
  const criteriaMap = [
    [DOM.critLength,  hasLength],
    [DOM.critUpper,   hasUpper],
    [DOM.critLower,   hasLower],
    [DOM.critNumber,  hasNumber],
    [DOM.critSpecial, hasSpecial],
    [DOM.critLong,    hasLongLen],
  ];

  criteriaMap.forEach(([el, isMet]) => {
    const wasMet = el.getAttribute('data-met') === 'true';
    el.setAttribute('data-met', isMet ? 'true' : 'false');

    // Animation pulse uniquement quand le critère vient d'être validé
    if (isMet && !wasMet) {
      el.classList.add('just-met');
      // Retirer la classe après l'animation pour qu'elle puisse se rejouer
      el.addEventListener('animationend', () => el.classList.remove('just-met'), { once: true });
    }
  });

  /* — Conseils — */
  DOM.tipsList.innerHTML = tips
    .map(tip => `<li>${tip}</li>`)
    .join('');
}

/**
 * Réinitialise l'interface à son état vide (champ vide).
 */
function resetUI() {
  DOM.progressBar.style.width = '0%';
  DOM.progressBar.className = 'progress-fill';
  DOM.progressTrack.setAttribute('aria-valuenow', 0);

  DOM.strengthLabel.textContent = 'En attente…';
  DOM.strengthLabel.className = 'strength-label';
  DOM.strengthScore.textContent = '0 / 100';
  DOM.strengthScore.className = 'strength-score';

  // Remettre tous les critères à "non validé"
  [DOM.critLength, DOM.critUpper, DOM.critLower,
   DOM.critNumber, DOM.critSpecial, DOM.critLong].forEach(el => {
    el.setAttribute('data-met', 'false');
  });

  DOM.tipsList.innerHTML = '<li>Entrez un mot de passe pour recevoir des conseils personnalisés.</li>';
}

/* ────────────────────────────────────────────────────────────────
   7. GESTIONNAIRES D'ÉVÉNEMENTS
────────────────────────────────────────────────────────────────── */

/* — ANALYSEUR — */

/** Analyse en temps réel à chaque frappe */
DOM.passwordInput.addEventListener('input', () => {
  const value = DOM.passwordInput.value;
  if (value.length === 0) {
    resetUI();
    return;
  }
  const result = analyzePassword(value);
  updateUI(result);
});

/** Afficher / Masquer le mot de passe */
DOM.toggleBtn.addEventListener('click', () => {
  const isPassword = DOM.passwordInput.type === 'password';
  DOM.passwordInput.type = isPassword ? 'text' : 'password';
  DOM.toggleBtn.classList.toggle('revealed', isPassword);
  DOM.toggleBtn.setAttribute('aria-label',
    isPassword ? 'Masquer le mot de passe' : 'Afficher le mot de passe'
  );
  // Redonner le focus au champ (UX)
  DOM.passwordInput.focus();
});

/* — GÉNÉRATEUR — */

/** Mise à jour de l'affichage de la longueur au déplacement du slider */
DOM.genLength.addEventListener('input', () => {
  DOM.genLengthDisplay.textContent = DOM.genLength.value;
});

/** Générer un mot de passe au clic */
DOM.generateBtn.addEventListener('click', () => {
  const options = {
    length:      parseInt(DOM.genLength.value, 10),
    upper:       DOM.genUpper.checked,
    lower:       DOM.genLower.checked,
    numbers:     DOM.genNumbers.checked,
    special:     DOM.genSpecial.checked,
    noAmbiguous: DOM.genAmbiguous.checked,
  };

  const { password, alphabetSize } = generatePassword(options);

  DOM.generatedPassword.textContent = password;

  // Calcul et affichage de l'entropie
  const bits = calcEntropy(alphabetSize, password.length);
  DOM.entropyInfo.textContent =
    `Entropie : ${bits} bits — Sécurité ${entropyLabel(bits)} (alphabet de ${alphabetSize} caractères)`;

  // Réinitialiser l'état "copié" si présent
  DOM.copyBtn.classList.remove('copied');
});

/** Copier le mot de passe généré dans le presse-papier */
DOM.copyBtn.addEventListener('click', async () => {
  const password = DOM.generatedPassword.textContent;
  // Pas de mot de passe généré = on ignore
  if (!password || password === 'Cliquez sur Générer…') return;

  try {
    await navigator.clipboard.writeText(password);
    DOM.copyBtn.classList.add('copied');
    // Remettre l'icône copier après 2 secondes
    setTimeout(() => DOM.copyBtn.classList.remove('copied'), 2000);
  } catch (err) {
    // Fallback pour les navigateurs sans Clipboard API
    const textArea = document.createElement('textarea');
    textArea.value = password;
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand('copy');
    document.body.removeChild(textArea);
    DOM.copyBtn.classList.add('copied');
    setTimeout(() => DOM.copyBtn.classList.remove('copied'), 2000);
  }
});

/**
 * Analyser le mot de passe généré :
 * le copie dans le champ analyseur et déclenche l'analyse.
 */
DOM.analyzeGenBtn.addEventListener('click', () => {
  const password = DOM.generatedPassword.textContent;
  if (!password || password === 'Cliquez sur Générer…') return;

  DOM.passwordInput.value = password;
  // Déclencher manuellement l'événement input pour lancer l'analyse
  DOM.passwordInput.dispatchEvent(new Event('input'));
  // Scroll vers le haut pour voir les résultats
  DOM.passwordInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
  DOM.passwordInput.focus();
});

/* ────────────────────────────────────────────────────────────────
   8. INITIALISATION
────────────────────────────────────────────────────────────────── */

/**
 * Initialisation au chargement de la page.
 * — Met à jour l'affichage du slider avec la valeur par défaut.
 * — S'assure que l'état de l'UI est propre.
 */
(function init() {
  // Synchroniser l'affichage du slider
  DOM.genLengthDisplay.textContent = DOM.genLength.value;

  // S'assurer que l'état est propre au démarrage
  resetUI();

  console.log('%cCipherGuard v1.0 — Password Analyzer initialized', 'color:#00e5ff;font-family:monospace;');
})();
