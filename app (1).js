/* MOONSLOT — Firebase + interfaz
 * Pega la configuración WEB de Firebase en FIREBASE_CONFIG.
 * No añadas aquí claves privadas, service accounts ni credenciales de Firebase Admin.
 */
const FIREBASE_CONFIG = Object.freeze({
  apiKey: "",
  authDomain: "",
  projectId: "",
  appId: "",
  messagingSenderId: "",
  storageBucket: ""
});

const $ = (id) => document.getElementById(id);
const viewIds = ['landing-section', 'login-section', 'app-section'];
let currentView = 'landing-section';
let authInstance = null;
let firebaseAuthApi = null;

function showView(viewId) {
  if (!viewIds.includes(viewId)) return;
  currentView = viewId;
  for (const id of viewIds) $(id).classList.toggle('hidden', id !== viewId);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showLoginError(message) {
  const box = $('login-error');
  box.textContent = String(message || 'No se pudo iniciar sesión.');
  box.classList.remove('hidden');
}

function clearLoginError() {
  $('login-error').textContent = '';
  $('login-error').classList.add('hidden');
}

function setUser(user) {
  if (user) {
    $('user-email').textContent = user.email || 'Sesión activa';
    showView('app-section');
  } else {
    $('user-email').textContent = '';
    if (currentView === 'app-section') showView('landing-section');
  }
}

function firebaseConfigIsReady() {
  return ['apiKey', 'authDomain', 'projectId', 'appId'].every((key) =>
    typeof FIREBASE_CONFIG[key] === 'string' && FIREBASE_CONFIG[key].trim().length > 0
  );
}

async function initializeFirebase() {
  if (!firebaseConfigIsReady()) {
    console.info('[Moonslot] Firebase aún no está configurado.');
    return;
  }

  try {
    const sdkBase = 'https://www.gstatic.com/firebasejs/10.12.5/';
    const appSdk = await import(`${sdkBase}firebase-app.js`);
    const authSdk = await import(`${sdkBase}firebase-auth.js`);
    const firebaseApp = appSdk.initializeApp(FIREBASE_CONFIG);
    authInstance = authSdk.getAuth(firebaseApp);
    firebaseAuthApi = authSdk;
    const provider = new authSdk.GoogleAuthProvider();
    provider.setCustomParameters({ prompt: 'select_account' });
    window.MOONSLOT_GOOGLE_PROVIDER = provider;
    authSdk.onAuthStateChanged(authInstance, setUser, (error) => {
      console.error('[Moonslot] Error de estado de autenticación:', error);
      showLoginError('No se pudo comprobar la sesión. Vuelve a intentarlo.');
    });
  } catch (error) {
    console.error('[Moonslot] No se pudo inicializar Firebase:', error);
    showLoginError('No se pudo conectar con Firebase. Revisa la configuración y los dominios autorizados.');
  }
}

async function signIn() {
  clearLoginError();
  if (!firebaseConfigIsReady() || !authInstance || !firebaseAuthApi) {
    showLoginError('Firebase todavía no está configurado. Completa FIREBASE_CONFIG en app.js.');
    return;
  }
  try {
    const provider = window.MOONSLOT_GOOGLE_PROVIDER;
    await firebaseAuthApi.signInWithPopup(authInstance, provider);
  } catch (error) {
    console.error('[Moonslot] Error de inicio de sesión:', error);
    const messages = {
      'auth/popup-closed-by-user': 'Has cerrado la ventana de acceso antes de terminar.',
      'auth/unauthorized-domain': 'Este dominio no está autorizado en la configuración de Firebase.',
      'auth/popup-blocked': 'El navegador ha bloqueado la ventana de acceso. Permite las ventanas emergentes.'
    };
    showLoginError(messages[error.code] || 'No se pudo iniciar sesión con Google. Inténtalo de nuevo.');
  }
}

async function signOut() {
  if (!authInstance || !firebaseAuthApi) {
    setUser(null);
    return;
  }
  try {
    await firebaseAuthApi.signOut(authInstance);
  } catch (error) {
    console.error('[Moonslot] Error al cerrar sesión:', error);
    showLoginError('No se pudo cerrar la sesión. Inténtalo de nuevo.');
  }
}

async function refreshServiceStatus() {
  const indicator = $('service-indicator');
  const status = $('service-status');
  const detail = $('service-detail');
  status.textContent = 'Comprobando servicio';
  detail.textContent = 'Conectando con Moonslot API…';
  indicator.className = 'status-indicator';
  try {
    const response = await fetch('/health', {
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    });
    if (!response.ok) throw new Error('Servicio no disponible');
    const data = await response.json();
    if (data.status !== 'healthy') throw new Error('Estado inesperado');
    indicator.classList.add('online');
    status.textContent = 'Servicio operativo';
    detail.textContent = 'Moonslot API responde correctamente.';
  } catch (error) {
    indicator.classList.add('offline');
    status.textContent = 'No se pudo conectar';
    detail.textContent = 'Comprueba el servidor e inténtalo de nuevo.';
  }
}

document.querySelectorAll('[data-open-login]').forEach((button) => {
  button.addEventListener('click', () => {
    clearLoginError();
    showView('login-section');
  });
});
document.querySelectorAll('[data-back]').forEach((button) => {
  button.addEventListener('click', () => showView('landing-section'));
});
$('google-login').addEventListener('click', signIn);
$('logout-btn').addEventListener('click', signOut);
$('refresh-status').addEventListener('click', refreshServiceStatus);
$('year').textContent = String(new Date().getFullYear());
refreshServiceStatus();
initializeFirebase();
