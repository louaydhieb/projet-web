/**
 * main.js – Logique frontend principale
 * Fonctions utilitaires communes à toutes les pages
 */

// ─────────────────────────────────────────────
//  CSRF TOKEN INTERCEPTOR
// ─────────────────────────────────────────────

const originalFetch = window.fetch;
window.fetch = async function() {
  let [resource, config] = arguments;
  if (config && config.method && !['GET', 'HEAD', 'OPTIONS'].includes(config.method.toUpperCase())) {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
      config.headers = {
        ...config.headers,
        "X-CSRFToken": csrfMeta.getAttribute('content')
      };
    }
  }
  return originalFetch(resource, config);
};

// ─────────────────────────────────────────────
//  ALERTES GLOBALES
// ─────────────────────────────────────────────

/**
 * Affiche une alerte globale en haut à droite de l'écran.
 * @param {string} message - Le message à afficher.
 * @param {string} type - 'success' ou 'danger'.
 */
function showGlobalAlert(message, type = "success") {
  const alertEl = document.getElementById("globalAlert");
  const msgEl   = document.getElementById("globalAlertMsg");
  if (!alertEl || !msgEl) return;

  alertEl.className = `global-alert alert-${type}`;
  msgEl.textContent = message;
  alertEl.classList.remove("d-none");

  // Fermeture automatique après 4 secondes
  setTimeout(() => alertEl.classList.add("d-none"), 4000);
}

/** Ferme manuellement l'alerte globale. */
function hideAlert() {
  const alertEl = document.getElementById("globalAlert");
  if (alertEl) alertEl.classList.add("d-none");
}


// ─────────────────────────────────────────────
//  DÉCONNEXION
// ─────────────────────────────────────────────

/**
 * Envoie une requête de déconnexion puis redirige vers l'accueil.
 * Détruit la session côté serveur (cookie httpOnly invalidé).
 */
async function logout() {
  try {
    const res = await fetch("/api/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    if (res.ok) {
      showGlobalAlert("Déconnexion réussie. À bientôt !", "success");
      setTimeout(() => window.location.href = "/", 800);
    }
  } catch {
    window.location.href = "/";
  }
}


// ─────────────────────────────────────────────
//  AFFICHER/MASQUER MOT DE PASSE
// ─────────────────────────────────────────────

/**
 * Bascule la visibilité d'un champ mot de passe.
 * @param {string} inputId - L'ID du champ input.
 * @param {string} btnId   - L'ID du bouton toggle.
 */
function togglePassword(inputId, btnId) {
  const input = document.getElementById(inputId);
  const btn   = document.getElementById(btnId);
  if (!input || !btn) return;

  const icon = btn.querySelector("i");
  if (input.type === "password") {
    input.type = "text";
    icon.className = "bi bi-eye-slash";
  } else {
    input.type = "password";
    icon.className = "bi bi-eye";
  }
}


// ─────────────────────────────────────────────
//  BOUTON CHARGEMENT
// ─────────────────────────────────────────────

/**
 * Active ou désactive l'état de chargement d'un bouton.
 * @param {HTMLButtonElement} btn     - Le bouton à modifier.
 * @param {boolean}           loading - True pour activer le spinner.
 */
function setBtnLoading(btn, loading) {
  if (!btn) return;
  const textEl    = btn.querySelector(".btn-text");
  const spinnerEl = btn.querySelector(".btn-spinner");

  if (loading) {
    textEl?.classList.add("d-none");
    spinnerEl?.classList.remove("d-none");
    btn.disabled = true;
  } else {
    textEl?.classList.remove("d-none");
    spinnerEl?.classList.add("d-none");
    btn.disabled = false;
  }
}


// ─────────────────────────────────────────────
//  COPIER DANS LE PRESSE-PAPIERS
// ─────────────────────────────────────────────

/**
 * Copie le contenu textuel d'un élément dans le presse-papiers.
 * @param {string} elementId - L'ID de l'élément dont copier le texte.
 */
async function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;

  try {
    await navigator.clipboard.writeText(el.textContent.trim());
    showGlobalAlert("Copié dans le presse-papiers !", "success");
  } catch {
    // Fallback pour les navigateurs sans Clipboard API
    const range = document.createRange();
    range.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(range);
    document.execCommand("copy");
    window.getSelection().removeAllRanges();
    showGlobalAlert("Copié !", "success");
  }
}


// ─────────────────────────────────────────────
//  NAVBAR SCROLL EFFECT
// ─────────────────────────────────────────────

window.addEventListener("scroll", () => {
  const nav = document.getElementById("mainNav");
  if (!nav) return;
  if (window.scrollY > 20) {
    nav.style.background = "rgba(10, 14, 26, 0.97)";
  } else {
    nav.style.background = "rgba(10, 14, 26, 0.85)";
  }
}, { passive: true });


// ─────────────────────────────────────────────
//  EXPIRATION DE SESSION
// ─────────────────────────────────────────────

/**
 * Avertit l'utilisateur 5 minutes avant l'expiration de sa session.
 * La session expire après 30 minutes d'inactivité côté serveur.
 */
(function initSessionWarning() {
  // Si on est sur une page protégée (navbar avec bouton logout)
  const logoutBtn = document.getElementById("logoutBtn");
  if (!logoutBtn) return;

  // Avertissement 5 min avant l'expiration (30 - 5 = 25 min)
  const WARNING_MS = 25 * 60 * 1000;
  let warningTimer = setTimeout(() => {
    showGlobalAlert(
      "⚠️ Votre session expirera dans 5 minutes d'inactivité.",
      "danger"
    );
  }, WARNING_MS);

  // Réinitialisation du timer à chaque interaction
  const events = ["click", "keydown", "mousemove", "scroll", "touchstart"];
  let resetTimeout = null;
  events.forEach(evt => {
    document.addEventListener(evt, () => {
      clearTimeout(warningTimer);
      clearTimeout(resetTimeout);
      // Debounce – ne reset qu'après 5 secondes d'inactivité
      resetTimeout = setTimeout(() => {
        warningTimer = setTimeout(() => {
          showGlobalAlert(
            "⚠️ Votre session expirera dans 5 minutes d'inactivité.",
            "danger"
          );
        }, WARNING_MS);
      }, 5000);
    }, { passive: true });
  });
})();


// ─────────────────────────────────────────────
//  UTILITAIRE : VALIDATION RÈGLES MDP
// (utilisé sur register.html et password.html)
// ─────────────────────────────────────────────

function updateRule(id, valid) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle("rule-valid", valid);
  el.classList.toggle("rule-invalid", !valid);
  const icon = el.querySelector("i");
  if (icon) {
    icon.className = valid
      ? "bi bi-check-circle me-1 text-success"
      : "bi bi-x-circle me-1 text-danger";
  }
}
