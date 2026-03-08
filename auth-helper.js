// ==================== AUTHENTICATION HELPER ====================
// Include this file in your dashboard and protected pages
// <script src="auth-helper.js"></script>

// ==================== CONFIGURATION ====================

const AUTH_CONFIG = {
  // Supabase configuration (replace with your values)
  SUPABASE_URL: 'YOUR_SUPABASE_URL',
  SUPABASE_ANON_KEY: 'YOUR_SUPABASE_ANON_KEY',
  
  // Routes
  LOGIN_PAGE: 'rookieagent-auth.html',
  DASHBOARD_PAGE: 'rookieagent-dashboard.html',
  
  // Session settings
  SESSION_KEY: 'rookieagent_user',
  SESSION_TIMEOUT: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
};

// ==================== SESSION MANAGEMENT ====================

class AuthManager {
  
  constructor() {
    this.user = null;
    this.init();
  }
  
  init() {
    // Load user from localStorage
    const userData = localStorage.getItem(AUTH_CONFIG.SESSION_KEY);
    if (userData) {
      try {
        this.user = JSON.parse(userData);
      } catch (error) {
        console.error('Failed to parse user data:', error);
        this.clearSession();
      }
    }
  }
  
  // Check if user is authenticated
  isAuthenticated() {
    if (!this.user) return false;
    
    // Check session expiration
    if (this.user.expiresAt && new Date(this.user.expiresAt) < new Date()) {
      this.clearSession();
      return false;
    }
    
    return true;
  }
  
  // Get current user
  getCurrentUser() {
    return this.user;
  }
  
  // Save session
  saveSession(userData) {
    // Add expiration if "remember me" is enabled
    if (userData.remember) {
      userData.expiresAt = new Date(Date.now() + AUTH_CONFIG.SESSION_TIMEOUT).toISOString();
    }
    
    this.user = userData;
    localStorage.setItem(AUTH_CONFIG.SESSION_KEY, JSON.stringify(userData));
  }
  
  // Clear session
  clearSession() {
    this.user = null;
    localStorage.removeItem(AUTH_CONFIG.SESSION_KEY);
  }
  
  // Logout
  logout() {
    this.clearSession();
    window.location.href = AUTH_CONFIG.LOGIN_PAGE;
  }
  
  // Require authentication (use on protected pages)
  requireAuth() {
    if (!this.isAuthenticated()) {
      // Store intended destination
      sessionStorage.setItem('redirect_after_login', window.location.href);
      // Redirect to login
      window.location.href = AUTH_CONFIG.LOGIN_PAGE;
      return false;
    }
    return true;
  }
  
  // Redirect after login
  redirectAfterLogin() {
    const redirect = sessionStorage.getItem('redirect_after_login');
    if (redirect) {
      sessionStorage.removeItem('redirect_after_login');
      window.location.href = redirect;
    } else {
      window.location.href = AUTH_CONFIG.DASHBOARD_PAGE;
    }
  }
  
  // Get user display name
  getUserDisplayName() {
    if (!this.user) return 'User';
    return `${this.user.firstName || ''} ${this.user.lastName || ''}`.trim() || this.user.email || 'User';
  }
  
  // Get user initials
  getUserInitials() {
    if (!this.user) return 'U';
    const first = (this.user.firstName || '')[0] || '';
    const last = (this.user.lastName || '')[0] || '';
    return (first + last).toUpperCase() || (this.user.email || 'U')[0].toUpperCase();
  }
  
}

// Create global instance
const auth = new AuthManager();

// ==================== PROTECTED ROUTE GUARD ====================

// Call this function at the top of protected pages
function protectRoute() {
  return auth.requireAuth();
}

// ==================== AUTO-REDIRECT IF LOGGED IN ====================

// Call this on auth pages (login, signup) to redirect if already logged in
function redirectIfAuthenticated() {
  if (auth.isAuthenticated()) {
    window.location.href = AUTH_CONFIG.DASHBOARD_PAGE;
  }
}

// ==================== LOGOUT FUNCTION ====================

function logout() {
  if (confirm('Are you sure you want to logout?')) {
    auth.logout();
  }
}

// ==================== UI HELPERS ====================

// Update user info in UI
function updateUserUI() {
  const user = auth.getCurrentUser();
  if (!user) return;
  
  // Update avatar
  const avatars = document.querySelectorAll('[data-user-avatar]');
  avatars.forEach(avatar => {
    avatar.textContent = auth.getUserInitials();
  });
  
  // Update name
  const names = document.querySelectorAll('[data-user-name]');
  names.forEach(nameEl => {
    nameEl.textContent = auth.getUserDisplayName();
  });
  
  // Update email
  const emails = document.querySelectorAll('[data-user-email]');
  emails.forEach(emailEl => {
    emailEl.textContent = user.email || '';
  });
}

// ==================== RATE LIMITING ====================

class RateLimiter {
  constructor(maxAttempts = 5, windowMs = 15 * 60 * 1000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = new Map();
  }
  
  checkLimit(key) {
    const now = Date.now();
    const attempts = this.attempts.get(key) || [];
    
    // Remove old attempts outside the window
    const recentAttempts = attempts.filter(time => now - time < this.windowMs);
    
    if (recentAttempts.length >= this.maxAttempts) {
      const oldestAttempt = Math.min(...recentAttempts);
      const timeUntilReset = this.windowMs - (now - oldestAttempt);
      const minutesLeft = Math.ceil(timeUntilReset / 60000);
      
      throw new Error(`Too many attempts. Please try again in ${minutesLeft} minute${minutesLeft > 1 ? 's' : ''}.`);
    }
    
    // Add new attempt
    recentAttempts.push(now);
    this.attempts.set(key, recentAttempts);
    
    return true;
  }
  
  reset(key) {
    this.attempts.delete(key);
  }
}

// Create rate limiter instances
const loginLimiter = new RateLimiter(5, 15 * 60 * 1000); // 5 attempts per 15 minutes
const signupLimiter = new RateLimiter(3, 60 * 60 * 1000); // 3 attempts per hour

// ==================== INPUT VALIDATION ====================

const validation = {
  
  // Email validation
  isValidEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
  },
  
  // Password validation
  isValidPassword(password) {
    return password.length >= 8;
  },
  
  // Strong password check
  isStrongPassword(password) {
    const checks = {
      length: password.length >= 12,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^a-zA-Z0-9]/.test(password)
    };
    
    const passedChecks = Object.values(checks).filter(Boolean).length;
    return passedChecks >= 4;
  },
  
  // Sanitize input
  sanitize(input) {
    return input.trim().replace(/[<>]/g, '');
  }
  
};

// ==================== ERROR HANDLER ====================

function handleAuthError(error) {
  console.error('Authentication error:', error);
  
  // Map common errors to user-friendly messages
  const errorMessages = {
    'Invalid email or password': 'The email or password you entered is incorrect.',
    'User already exists': 'An account with this email already exists.',
    'Invalid token': 'Your session has expired. Please login again.',
    'Network error': 'Unable to connect. Please check your internet connection.',
  };
  
  const message = errorMessages[error.message] || error.message || 'An error occurred. Please try again.';
  
  return message;
}

// ==================== SESSION REFRESH ====================

// Refresh session periodically to keep user logged in
function startSessionRefresh(intervalMinutes = 30) {
  setInterval(() => {
    if (auth.isAuthenticated()) {
      // In production, refresh token with Supabase
      // await supabase.auth.refreshSession();
      
      // For demo, just update last activity
      const user = auth.getCurrentUser();
      if (user) {
        user.lastActivity = new Date().toISOString();
        auth.saveSession(user);
      }
    }
  }, intervalMinutes * 60 * 1000);
}

// ==================== INITIALIZE ====================

// Auto-start session refresh
if (typeof window !== 'undefined') {
  startSessionRefresh(30);
  
  // Update UI on load
  window.addEventListener('DOMContentLoaded', () => {
    updateUserUI();
  });
}

// ==================== EXPORTS ====================

// Make functions available globally
if (typeof window !== 'undefined') {
  window.auth = auth;
  window.protectRoute = protectRoute;
  window.redirectIfAuthenticated = redirectIfAuthenticated;
  window.logout = logout;
  window.updateUserUI = updateUserUI;
  window.loginLimiter = loginLimiter;
  window.signupLimiter = signupLimiter;
  window.validation = validation;
  window.handleAuthError = handleAuthError;
}

// ==================== USAGE EXAMPLES ====================

/*

1. PROTECT A DASHBOARD PAGE:

Add this to the top of your dashboard HTML:

<script src="auth-helper.js"></script>
<script>
  // Redirect to login if not authenticated
  if (!protectRoute()) {
    // User will be redirected
  }
</script>


2. REDIRECT IF ALREADY LOGGED IN (on auth pages):

<script src="auth-helper.js"></script>
<script>
  // Redirect to dashboard if already logged in
  redirectIfAuthenticated();
</script>


3. SHOW USER INFO IN UI:

<div class="user-card">
  <div class="user-avatar" data-user-avatar></div>
  <div class="user-info">
    <div class="user-name" data-user-name></div>
    <div class="user-email" data-user-email></div>
  </div>
</div>

<script>
  // Auto-populates on load
  updateUserUI();
</script>


4. LOGOUT BUTTON:

<button onclick="logout()">Logout</button>


5. WITH RATE LIMITING:

async function handleLogin() {
  try {
    // Check rate limit
    loginLimiter.checkLimit('login');
    
    // Proceed with login
    // ...
    
    // On success, reset rate limit
    loginLimiter.reset('login');
    
  } catch (error) {
    showToast(error.message, 'error');
  }
}


6. WITH VALIDATION:

function validateSignup() {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  
  if (!validation.isValidEmail(email)) {
    throw new Error('Please enter a valid email address');
  }
  
  if (!validation.isValidPassword(password)) {
    throw new Error('Password must be at least 8 characters');
  }
  
  return true;
}

*/
