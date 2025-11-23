// src/utils/activityWatcher.js
import axios from 'axios';

const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // must match backend ACCESS_EXPIRES_MS (15m)
const EXTEND_THROTTLE_MS = 10 * 1000;   // don't call extend more than once every 10s
let idleTimer = null;
let onIdleWarning = null;
let lastExtend = 0;

export function setIdleWarningCallback(cb) {
  onIdleWarning = cb;
}

function callExtend() {
  const now = Date.now();
  if (now - lastExtend < EXTEND_THROTTLE_MS) return;
  lastExtend = now;

  axios.post('http://localhost:8081/auth/extend', {}, { withCredentials: true }).catch((err) => {
    // If extend fails with 401, token expired or invalid — redirect to login
    if (err.response && err.response.status === 401) {
      window.location.href = '/login';
    }// otherwise silent fail
  });
}

function resetIdleTimer() {
  // User is active → extend token
  callExtend();
  // Reset existing timer
  if (idleTimer) clearTimeout(idleTimer);

  idleTimer = setTimeout(() => {
    // 🔥 Trigger React UI warning
    if (onIdleWarning) {
      onIdleWarning("You have been idle. Your session will expire soon.");
    }

     // Start auto-logout timer
    setTimeout(() => {
      window.location.href = '/login'; // force logout
    }, 60 * 1000); // 1 minute after warning

  }, IDLE_TIMEOUT_MS - 60000);
}

export const startActivityWatcher =() => {
  const events = ['mousemove', 'mousedown', 'click', 'scroll', 'keydown', 'touchstart'];
  events.forEach(ev => window.addEventListener(ev, resetIdleTimer, { passive: true }));
  // start the timer immediately
  resetIdleTimer();
}

export function stopActivityWatcher() {
  const events = ['mousemove', 'mousedown', 'click', 'scroll', 'keydown', 'touchstart'];
  events.forEach(ev => window.removeEventListener(ev, resetIdleTimer));
  if (idleTimer) clearTimeout(idleTimer);
}
