import { firebaseConfig } from './firebase-config.js';

const SDK = 'https://www.gstatic.com/firebasejs/10.12.5/';
const $ = (id) => document.getElementById(id);

const views = { auth: $('view-auth'), app: $('view-app') };
let auth = null;
let sdk = null;

/* ---------- UI helpers ---------- */
function showView(name) {
  for (const [key, el] of Object.entries(views)) el.classList.toggle('hidden', key !== name);
  $('account').classList.toggle('hidden', name !== 'app');
  window.scrollTo({ top: 0 });
}

function showError(message) {
  const box = $('auth-error');
  box.textContent = message;
  box.classList.remove('hidden');
}
function clearError() {
  $('auth-error').textContent = '';
  $('auth-error').classList.add('hidden');
}
function setBusy(busy) {
  for (const id of ['login-google', 'login-github']) $(id).disabled = busy;
}

const PROVIDER_NAMES = { 'google.com': 'Google', 'github.com': 'GitHub' };

function renderUser(user) {
  const providerId = user.providerData[0]?.providerId;
  const name = user.displayName || user.email || 'Moonslot user';
  const avatar = $('user-avatar');
  if (user.photoURL) { avatar.src = user.photoURL; avatar.classList.remove('hidden'); }
  else { avatar.removeAttribute('src'); avatar.classList.add('hidden'); }
  $('user-name').textContent = name;
  $('app-title').textContent = user.displayName
    ? `Welcome back, ${user.displayName.split(' ')[0]}.`
    : 'Welcome back.';
  $('d-name').textContent = user.displayName || 'Not provided';
  $('d-email').textContent = user.email || 'Hidden by provider';
  $('d-provider').textContent = PROVIDER_NAMES[providerId] || providerId || 'Unknown';
  const last = user.metadata.lastSignInTime ? new Date(user.metadata.lastSignInTime) : null;
  $('d-last').textContent = last ? last.toLocaleString() : 'Just now';
}

/* ---------- Service status ---------- */
async function checkStatus() {
  const set = (cls, text, detail) => {
    for (const id of ['status-dot', 'footer-dot']) $(id).className = `dot ${cls}`;
    $('status-text').textContent = text;
    $('status-detail').textContent = detail;
    $('footer-text').textContent = text;
  };
  set('', 'Checking…', 'Contacting the Moonslot API.');
  try {
    const res = await fetch('/health', { headers: { Accept: 'application/json' }, cache: 'no-store' });
    const data = await res.json();
    if (!res.ok || data.status !== 'healthy') throw new Error('unhealthy');
    set('ok', 'All systems operational', 'The Moonslot API is responding normally.');
  } catch {
    set('bad', 'Service unreachable', 'The Moonslot API did not respond. Try again in a moment.');
  }
}

/* ---------- Authentication ---------- */
const AUTH_ERRORS = {
  'auth/popup-closed-by-user': 'The sign-in window was closed before you finished.',
  'auth/cancelled-popup-request': 'Another sign-in window is already open.',
  'auth/popup-blocked': 'Your browser blocked the sign-in window. Allow pop-ups for this site and try again.',
  'auth/unauthorized-domain': 'This domain is not authorized in Firebase. Add it under Authentication > Settings > Authorized domains.',
  'auth/operation-not-allowed': 'This sign-in method is not enabled yet. Enable it in Firebase Console > Authentication > Sign-in method.',
  'auth/account-exists-with-different-credential': 'An account with this email already exists using a different sign-in method. Sign in with that method first.',
  'auth/network-request-failed': 'Network error. Check your connection and try again.'
};

async function signInWith(providerName) {
  clearError();
  if (!auth || !sdk) { showError('Sign-in is not available right now. Reload the page and try again.'); return; }
  const provider = providerName === 'github'
    ? new sdk.GithubAuthProvider()
    : new sdk.GoogleAuthProvider();
  if (providerName === 'github') provider.addScope('user:email');
  else provider.setCustomParameters({ prompt: 'select_account' });
  setBusy(true);
  try {
    await sdk.signInWithPopup(auth, provider);
  } catch (error) {
    console.error('[Moonslot] Sign-in error:', error.code || error);
    showError(AUTH_ERRORS[error.code] || 'Could not sign you in. Please try again.');
  } finally {
    setBusy(false);
  }
}

async function signOut() {
  try { await sdk.signOut(auth); }
  catch (error) { console.error('[Moonslot] Sign-out error:', error); }
}

async function initFirebase() {
  try {
    const [appSdk, authSdk] = await Promise.all([
      import(`${SDK}firebase-app.js`),
      import(`${SDK}firebase-auth.js`)
    ]);
    const app = appSdk.initializeApp(firebaseConfig);
    sdk = authSdk;
    auth = authSdk.getAuth(app);
    authSdk.onAuthStateChanged(auth, (user) => {
      if (user) { renderUser(user); showView('app'); }
      else showView('auth');
    }, (error) => {
      console.error('[Moonslot] Auth state error:', error);
      showError('Could not check your session. Reload the page and try again.');
    });

    // Analytics is optional and must never block sign-in.
    import(`${SDK}firebase-analytics.js`)
      .then(async (a) => { if (await a.isSupported()) a.getAnalytics(app); })
      .catch(() => {});
  } catch (error) {
    console.error('[Moonslot] Firebase failed to load:', error);
    showError('Could not connect to Firebase. Check your connection and try again.');
  }
}

/* ---------- Init ---------- */
$('login-google').addEventListener('click', () => signInWith('google'));
$('login-github').addEventListener('click', () => signInWith('github'));
$('sign-out').addEventListener('click', signOut);
$('status-refresh').addEventListener('click', checkStatus);
$('year').textContent = String(new Date().getFullYear());
showView('auth');
checkStatus();
initFirebase();
