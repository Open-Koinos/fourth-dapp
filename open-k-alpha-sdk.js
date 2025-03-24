/**
 * Open-K-alpha-SDK
 * A lightweight JavaScript library for interacting with the Koinos blockchain via REST API
 * and integrating with the Kondor wallet using a message-based approach.
 * Features secure local storage with encryption, persistent sessions, and auto-logout.
 */

class OpenKAlphaSDK {
    /**
     * Create a new Open-K-alpha-SDK instance
     * @param {Object} options - Configuration options
     * @param {string} options.apiUrl - The Koinos REST API URL (defaults to mainnet)
     * @param {number} options.timeout - Request timeout in milliseconds (default: 10000)
     * @param {boolean} options.debugMode - Enable debug logging (default: false)
     * @param {Function} options.messageHandler - Function to handle messages (default: none)
     * @param {number} options.storageTTL - Storage time-to-live in milliseconds (default: 24h)
     * @param {string} options.encryptionSalt - Salt for encryption (default: random)
     * @param {boolean} options.persistentSession - Enable persistent session across page refreshes (default: true)
     * @param {number} options.autoLogoutTimeout - Auto-logout timeout in milliseconds (default: 0 - disabled)
     * @param {boolean} options.trackUserActivity - Reset auto-logout timer on user activity (default: true)
     */
    constructor(options = {}) {
      // Set default options
      this.options = {
        apiUrl: options.apiUrl || 'https://api.koinos.io',
        timeout: options.timeout || 10000,
        debugMode: options.debugMode || false,
        messageHandler: options.messageHandler,
        storageTTL: options.storageTTL || 24 * 60 * 60 * 1000, // 24 hours
        encryptionSalt: options.encryptionSalt || this._generateRandomSalt(),
        persistentSession: options.persistentSession !== false, // Default to true
        autoLogoutTimeout: options.autoLogoutTimeout || 0, // Default to disabled
        trackUserActivity: options.trackUserActivity !== false // Default to true
      };
      
      // Auto-logout timer reference
      this.autoLogoutTimer = null;

      // Initialize components in proper order
      this.secureStorage = new SecureStorage({
        namespace: 'openkalpha',
        defaultTTL: this.options.storageTTL,
        debugMode: this.options.debugMode,
        salt: this.options.encryptionSalt
      });
      
      this.messageSystem = new MessageSystem(this);
      this.client = new KoinosClient(this);
      this.wallet = new KondorWallet(this);

      // Log initialized state if debug mode
      this._debug('Open-K-alpha-SDK initialized with options:', this.options);
      
      // Set up activity tracking if auto-logout is enabled
      if (this.options.autoLogoutTimeout > 0 && this.options.trackUserActivity) {
        this._setupActivityTracking();
      }
      
      // Auto-reconnect wallet if persistent session is enabled
      if (this.options.persistentSession) {
        this._tryAutoReconnect();
      }
    }

    /**
     * Connect to Kondor wallet
     * @param {Object} options - Connection options
     * @param {boolean} options.saveSession - Save session for persistence (default: true)
     * @returns {Promise<Object>} Connection result message
     */
    async connect(options = {}) {
      try {
        // Default to saving session unless explicitly set to false
        const saveSession = options.saveSession !== false;
        
        // Connect to wallet
        const address = await this.wallet.connect(saveSession);
        
        // Start auto-logout timer if enabled
        this._startAutoLogoutTimer();
        
        return this.messageSystem.createMessage('WALLET_CONNECTED', { address });
      } catch (error) {
        return this.messageSystem.createErrorMessage('WALLET_CONNECT_FAILED', error);
      }
    }

    /**
     * Disconnect from wallet
     * @param {Object} options - Disconnection options
     * @param {boolean} options.clearSession - Clear persistent session (default: true)
     * @returns {Object} Disconnection result message
     */
    disconnect(options = {}) {
      // Default to clearing session unless explicitly set to false
      const clearSession = options.clearSession !== false;
      
      // Clear auto-logout timer
      this._clearAutoLogoutTimer();
      
      // Disconnect wallet
      this.wallet.disconnect(clearSession);
      
      return this.messageSystem.createMessage('WALLET_DISCONNECTED');
    }

    /**
     * Check if wallet is connected
     * @returns {Object} Connection status message
     */
    isConnected() {
      const connected = this.wallet.isConnected();
      return this.messageSystem.createMessage('WALLET_STATUS', { 
        connected,
        address: connected ? this.wallet.getAddress() : null
      });
    }

    /**
     * Get the connected wallet address
     * @returns {Object} Wallet address message
     */
    getAddress() {
      const address = this.wallet.getAddress();
      return this.messageSystem.createMessage('WALLET_ADDRESS', { address });
    }

    /**
     * Register a callback for specific message types
     * @param {string} messageType - Type of message to listen for
     * @param {Function} callback - Function to call when message is received
     * @returns {Function} Function to unregister the callback
     */
    on(messageType, callback) {
      return this.messageSystem.registerCallback(messageType, callback);
    }
    
    /**
     * Sets or updates the auto-logout timeout
     * @param {number} timeoutMs - Timeout in milliseconds (0 to disable)
     * @returns {Object} Configuration update message
     */
    setAutoLogoutTimeout(timeoutMs) {
      // Update the timeout setting
      this.options.autoLogoutTimeout = timeoutMs;
      
      // Store the setting in secure storage
      this.secureStorage.setItem('autoLogoutTimeout', timeoutMs);
      
      // Clear existing timer
      this._clearAutoLogoutTimer();
      
      // Start new timer if enabled and wallet is connected
      if (timeoutMs > 0 && this.wallet.isConnected()) {
        this._startAutoLogoutTimer();
      }
      
      return this.messageSystem.createMessage('AUTO_LOGOUT_CONFIGURED', {
        timeout: timeoutMs,
        enabled: timeoutMs > 0
      });
    }
    
    /**
     * Gets the current auto-logout timeout
     * @returns {number} Current timeout in milliseconds
     */
    getAutoLogoutTimeout() {
      // Try to get from secure storage first (for persistence)
      const storedTimeout = this.secureStorage.getItem('autoLogoutTimeout');
      
      if (storedTimeout !== null) {
        // Update the instance option to match stored value
        this.options.autoLogoutTimeout = storedTimeout;
      }
      
      return this.options.autoLogoutTimeout;
    }

    /**
     * Debug logging
     * @private
     */
    _debug(...args) {
      if (this.options.debugMode) {
        console.log('[Open-K-alpha-SDK]', ...args);
      }
    }

    /**
     * Create error with improved details
     * @param {string} message - Error message
     * @param {Object} details - Additional error details
     * @returns {Error} Enhanced error object
     * @private
     */
    _createError(message, details = {}) {
      const error = new Error(message);
      error.details = details;
      return error;
    }

    /**
     * Generate a random salt for encryption
     * @returns {string} Random salt string
     * @private
     */
    _generateRandomSalt() {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
      let salt = '';
      for (let i = 0; i < 16; i++) {
        salt += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      return salt;
    }
    
    /**
     * Attempt to automatically reconnect to wallet from stored session
     * @private
     */
    async _tryAutoReconnect() {
      try {
        // Check if we have a stored address
        const storedAddress = this.wallet.getStoredAddress();
        
        if (storedAddress) {
          this._debug('Found stored wallet session, attempting auto-reconnect');
          
          // Check if Kondor is available
          if (typeof window.kondor === 'undefined') {
            this._debug('Waiting for Kondor wallet to be available');
            
            // Wait for Kondor to be available (max 10 seconds)
            await new Promise((resolve) => {
              const checkInterval = setInterval(() => {
                if (typeof window.kondor !== 'undefined') {
                  clearInterval(checkInterval);
                  resolve();
                }
              }, 500);
              
              // Timeout after 10 seconds
              setTimeout(() => {
                clearInterval(checkInterval);
                resolve();
              }, 10000);
            });
          }
          
          // If Kondor is available, try to reconnect
          if (typeof window.kondor !== 'undefined') {
            await this.wallet.validateAndReconnect();
            
            // Start auto-logout timer if enabled
            this._startAutoLogoutTimer();
            
            this._debug('Successfully auto-reconnected to wallet');
          } else {
            this._debug('Kondor wallet not available for auto-reconnect');
          }
        }
      } catch (error) {
        this._debug('Auto-reconnect failed:', error);
      }
    }
    
    /**
     * Set up user activity tracking for auto-logout
     * @private
     */
    _setupActivityTracking() {
      // List of events to track for user activity
      const activityEvents = [
        'mousedown', 'keydown', 'touchstart', 'scroll'
      ];
      
      // Function to handle user activity
      const handleUserActivity = () => {
        // Only reset timer if wallet is connected and auto-logout is enabled
        if (this.wallet.isConnected() && this.options.autoLogoutTimeout > 0) {
          this._resetAutoLogoutTimer();
        }
      };
      
      // Add event listeners
      activityEvents.forEach(eventName => {
        window.addEventListener(eventName, handleUserActivity, { passive: true });
      });
      
      this._debug('Activity tracking set up for auto-logout');
    }
    
    /**
     * Start the auto-logout timer
     * @private
     */
    _startAutoLogoutTimer() {
        // Only start if auto-logout is enabled
        if (this.options.autoLogoutTimeout > 0) {
        this._debug(`Starting auto-logout timer for ${this.options.autoLogoutTimeout}ms`);
        
        // Clear any existing timer
        this._clearAutoLogoutTimer();
        
        // Set new timer
        this.autoLogoutTimer = setTimeout(() => {
            this._debug('Auto-logout timer expired, disconnecting wallet');
            this.disconnect();
            
            // Notify about auto-logout
            this.messageSystem.createMessage('AUTO_LOGOUT', {
            reason: 'timeout',
            timeout: this.options.autoLogoutTimeout
            });
        }, this.options.autoLogoutTimeout);
        
        // Store the session expiry time
        const expiresAt = Date.now() + this.options.autoLogoutTimeout;
        this.secureStorage.setItem('session.expiryTime', expiresAt, this.options.autoLogoutTimeout);
        }
    }
  
    
    /**
     * Reset the auto-logout timer
     * @private
     */
    _resetAutoLogoutTimer() {
      this._clearAutoLogoutTimer();
      this._startAutoLogoutTimer();
    }
    
    /**
     * Clear the auto-logout timer
     * @private
     */
    _clearAutoLogoutTimer() {
      if (this.autoLogoutTimer) {
        clearTimeout(this.autoLogoutTimer);
        this.autoLogoutTimer = null;
      }
    }
}

/**
 * Message system for standardized communication
 */
class MessageSystem {
  /**
   * Create a new message system
   * @param {OpenKAlphaSDK} sdk - Parent SDK instance
   */
  constructor(sdk) {
    this.sdk = sdk;
    this.callbacks = new Map();
  }

  /**
 * Create a standardized message
 * @param {string} type - Message type
 * @param {Object} data - Message data
 * @returns {Object} Formatted message
 */
createMessage(type, data = {}) {
    const message = {
    type,
    data,
    timestamp: Date.now()
    };

    // Filter out noisy messages:
    // 1. Don't log API_RESPONSE messages
    // 2. Don't log WALLET_STATUS messages which are used for the timer
    // 3. Only log if message handler exists
    const shouldLog = 
    typeof this.sdk.options.messageHandler === 'function' && 
    !type.includes('API_RESPONSE') && 
    type !== 'WALLET_STATUS';
    
    if (shouldLog) {
    this.sdk.options.messageHandler(message);
    }

    // Still notify callbacks even for filtered messages
    this._notifyCallbacks(type, message);

    return message;
}

  /**
   * Create standardized error message
   * @param {string} type - Error type
   * @param {Error} error - Error object
   * @returns {Object} Error message
   */
  createErrorMessage(type, error) {
    const errorData = {
      message: error.message,
      details: error.details || {}
    };

    return this.createMessage(type, {
      error: errorData,
      success: false
    });
  }

  /**
   * Register a callback for a specific message type
   * @param {string} type - Message type to listen for
   * @param {Function} callback - Function to call
   * @returns {Function} Function to unregister callback
   */
  registerCallback(type, callback) {
    if (typeof callback !== 'function') {
      this.sdk._debug('Invalid callback provided');
      return () => {};
    }

    if (!this.callbacks.has(type)) {
      this.callbacks.set(type, new Set());
    }

    this.callbacks.get(type).add(callback);
    
    // Return unregister function
    return () => {
      if (this.callbacks.has(type)) {
        this.callbacks.get(type).delete(callback);
      }
    };
  }

  /**
   * Notify all callbacks for a specific message type
   * @param {string} type - Message type
   * @param {Object} message - Message to send
   * @private
   */
  _notifyCallbacks(type, message) {
    if (!this.callbacks.has(type)) return;

    for (const callback of this.callbacks.get(type)) {
      try {
        callback(message);
      } catch (error) {
        this.sdk._debug('Error in message callback:', error);
      }
    }
  }
}

/**
 * Secure Storage utility with encryption and timeout
 */
class SecureStorage {
  /**
   * Create a new SecureStorage instance
   * @param {Object} options - Configuration options
   * @param {string} options.namespace - Storage namespace prefix
   * @param {number} options.defaultTTL - Default time-to-live in milliseconds
   * @param {boolean} options.debugMode - Enable debug logging
   * @param {string} options.salt - Encryption salt
   */
  constructor(options = {}) {
    this.namespace = options.namespace || 'secure_storage';
    this.defaultTTL = options.defaultTTL || 24 * 60 * 60 * 1000; // 24 hours default
    this.debugMode = options.debugMode || false;
    this.salt = options.salt || 'default-salt';
    
    // Generate a domain-specific key for added security
    this.domainKey = this._getDomainSpecificKey();
    
    // Run cleanup of expired items on initialization
    this._cleanupExpiredItems();
  }
  
  /**
   * Store encrypted data with expiration
   * @param {string} key - Storage key
   * @param {any} data - Data to store
   * @param {number} ttl - Time to live in milliseconds (optional)
   */
  setItem(key, data, ttl) {
    const storageKey = this._getNamespacedKey(key);
    const expiresAt = Date.now() + (ttl || this.defaultTTL);
    
    const storageData = {
      data,
      expiresAt
    };
    
    try {
      const encryptedData = this._encrypt(JSON.stringify(storageData));
      localStorage.setItem(storageKey, encryptedData);
      this._debug(`Stored encrypted data for key: ${key}, expires: ${new Date(expiresAt).toLocaleString()}`);
    } catch (error) {
      this._debug(`Error storing data for key ${key}:`, error);
    }
  }
  
  /**
   * Retrieve and decrypt data if not expired
   * @param {string} key - Storage key
   * @returns {any} Decrypted data or null if expired/not found
   */
  getItem(key) {
    const storageKey = this._getNamespacedKey(key);
    const encryptedData = localStorage.getItem(storageKey);
    
    if (!encryptedData) {
      return null;
    }
    
    try {
      const decryptedString = this._decrypt(encryptedData);
      const storageData = JSON.parse(decryptedString);
      
      // Check if data has expired
      if (storageData.expiresAt < Date.now()) {
        this._debug(`Data for key ${key} has expired, removing`);
        this.removeItem(key);
        return null;
      }
      
      this._debug(`Retrieved data for key: ${key}, expires: ${new Date(storageData.expiresAt).toLocaleString()}`);
      return storageData.data;
    } catch (error) {
      // If decryption fails or data is invalid, remove the item
      this._debug(`Error decrypting data for key ${key}:`, error);
      this.removeItem(key);
      return null;
    }
  }
  
  /**
   * Get expiration timestamp for a key
   * @param {string} key - Storage key
   * @returns {number|null} Expiration timestamp or null if key not found
   */
  getExpiry(key) {
    const storageKey = this._getNamespacedKey(key);
    const encryptedData = localStorage.getItem(storageKey);
    
    if (!encryptedData) {
      return null;
    }
    
    try {
      const decryptedString = this._decrypt(encryptedData);
      const storageData = JSON.parse(decryptedString);
      return storageData.expiresAt;
    } catch (error) {
      return null;
    }
  }
  
  /**
   * Remove item from storage
   * @param {string} key - Storage key
   */
  removeItem(key) {
    const storageKey = this._getNamespacedKey(key);
    localStorage.removeItem(storageKey);
    this._debug(`Removed data for key: ${key}`);
  }
  
  /**
   * Clear all items in this namespace
   */
  clear() {
    const itemsToRemove = [];
    
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(`${this.namespace}.`)) {
        itemsToRemove.push(key);
      }
    }
    
    // Remove items in a separate loop to avoid index shifting issues
    itemsToRemove.forEach(key => {
      localStorage.removeItem(key);
    });
    
    this._debug(`Cleared all ${itemsToRemove.length} items in namespace: ${this.namespace}`);
  }
  
  /**
   * Clean up expired items across all namespaces
   * @private
   */
  _cleanupExpiredItems() {
    const now = Date.now();
    const itemsToCheck = [];
    
    // Collect all items belonging to this namespace
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(`${this.namespace}.`)) {
        itemsToCheck.push(key);
      }
    }
    
    // Check each item for expiration
    let expiredCount = 0;
    itemsToCheck.forEach(storageKey => {
      try {
        const encryptedData = localStorage.getItem(storageKey);
        if (encryptedData) {
          const decryptedString = this._decrypt(encryptedData);
          const storageData = JSON.parse(decryptedString);
          
          if (storageData.expiresAt < now) {
            localStorage.removeItem(storageKey);
            expiredCount++;
          }
        }
      } catch (error) {
        // If we can't decrypt or parse, remove the item
        localStorage.removeItem(storageKey);
        expiredCount++;
      }
    });
    
    if (expiredCount > 0) {
      this._debug(`Cleaned up ${expiredCount} expired items`);
    }
  }
  
  /**
   * Generate a namespaced storage key
   * @param {string} key - Base key
   * @returns {string} Namespaced key
   * @private
   */
  _getNamespacedKey(key) {
    return `${this.namespace}.${key}`;
  }
  
  /**
   * Get a domain-specific key for encryption
   * @returns {string} Domain-specific key
   * @private
   */
  _getDomainSpecificKey() {
    const domain = window.location.hostname || 'localhost';
    const browserInfo = navigator.userAgent.slice(0, 10);
    return `${domain}:${browserInfo}:${this.salt}`;
  }
  
  /**
   * Simple encryption using XOR cipher with the domain key
   * @param {string} text - Text to encrypt
   * @returns {string} Encrypted text (base64)
   * @private
   */
  _encrypt(text) {
    const key = this.domainKey;
    let result = '';
    
    for (let i = 0; i < text.length; i++) {
      const charCode = text.charCodeAt(i);
      const keyChar = key.charCodeAt(i % key.length);
      const encryptedChar = String.fromCharCode(charCode ^ keyChar);
      result += encryptedChar;
    }
    
    // Convert to base64 for storage
    return btoa(result);
  }
  
  /**
   * Decrypt data encrypted with the XOR cipher
   * @param {string} encryptedBase64 - Encrypted text (base64)
   * @returns {string} Decrypted text
   * @private
   */
  _decrypt(encryptedBase64) {
    // Convert from base64
    const encrypted = atob(encryptedBase64);
    const key = this.domainKey;
    let result = '';
    
    for (let i = 0; i < encrypted.length; i++) {
      const charCode = encrypted.charCodeAt(i);
      const keyChar = key.charCodeAt(i % key.length);
      const decryptedChar = String.fromCharCode(charCode ^ keyChar);
      result += decryptedChar;
    }
    
    return result;
  }
  
  /**
   * Debug logging
   * @private
   */
  _debug(...args) {
    if (this.debugMode) {
      console.log('[SecureStorage]', ...args);
    }
  }
}

/**
 * Koinos REST API client
 */
class KoinosClient {
  /**
   * Create a new KoinosClient
   * @param {OpenKAlphaSDK} sdk - Parent SDK instance
   */
  constructor(sdk) {
    this.sdk = sdk;
    this.baseUrl = sdk.options.apiUrl;
    this.timeout = sdk.options.timeout;
  }

  /**
   * Make an HTTP request to the Koinos REST API
   * @param {string} method - HTTP method (GET, POST)
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request data (for POST)
   * @param {Object} params - URL parameters (for GET)
   * @returns {Promise<any>} API response
   */
  async _request(method, endpoint, data = null, params = null) {
    const url = new URL(`${this.baseUrl}${endpoint}`);
    
    // Add query parameters if provided
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== undefined && params[key] !== null) {
          url.searchParams.append(key, params[key]);
        }
      });
    }

    const options = {
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    };

    // Add body for POST requests
    if (method === 'POST' && data) {
      options.body = JSON.stringify(data);
    }

    try {
      // Timeout handling
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);
      options.signal = controller.signal;

      this.sdk._debug(`API Request: ${method} ${url.toString()}`);
      
      const response = await fetch(url.toString(), options);
      clearTimeout(timeoutId);

      // Handle non-success responses
      if (!response.ok) {
        throw this.sdk._createError(`API Error: ${response.status}`, {
          status: response.status,
          statusText: response.statusText,
          endpoint
        });
      }

      const result = await response.json();
      this.sdk._debug('API Response:', result);
      
      return result;
    } catch (error) {
      if (error.name === 'AbortError') {
        throw this.sdk._createError('API request timed out', { endpoint });
      }
      
      // Notify about API error
      this.sdk.messageSystem.createErrorMessage('API_ERROR', error);
      
      throw error;
    }
  }

  /**
   * Get token data from a single API call
   * @param {string} contractId - Token contract address
   * @param {string} account - Account address (optional)
   * @returns {Promise<Object>} Token data
   */
  async getTokenData(contractId, account = null) {
    try {
      // Get token info - contains name, symbol, decimals
      const tokenInfo = await this._request('GET', `/v1/token/${contractId}/info`);
      
      // Get balance if account provided
      let balance = null;
      if (account) {
        const balanceResponse = await this._request('GET', `/v1/token/${contractId}/balance/${account}`);
        balance = balanceResponse.value;
      }
      
      // Return consolidated data
      return {
        contractId,
        name: tokenInfo.name,
        symbol: tokenInfo.symbol,
        decimals: tokenInfo.decimals,
        totalSupply: tokenInfo.total_supply,
        balance
      };
    } catch (error) {
      throw this.sdk._createError(`Failed to get token data: ${error.message}`, {
        contractId,
        account,
        originalError: error
      });
    }
  }

  /**
   * Account-related API endpoints
   * @returns {Object} Account API methods
   */
  accounts() {
    return {
      /**
       * Get token balance for an account
       * @param {string} account - Account address
       * @param {string} contractId - Token contract address
       * @returns {Promise<Object>} Token balance message
       */
      getBalance: async (account, contractId) => {
        try {
          const result = await this._request('GET', `/v1/account/${account}/balance/${contractId}`);
          return this.sdk.messageSystem.createMessage('ACCOUNT_BALANCE', {
            account,
            contractId,
            balance: result.value
          });
        } catch (error) {
          return this.sdk.messageSystem.createErrorMessage('ACCOUNT_BALANCE_ERROR', error);
        }
      }
    };
  }

  /**
   * Token-related API endpoints
   * @returns {Object} Token API methods
   */
  tokens() {
    return {
      /**
       * Get token balance for an account
       * @param {string} contractId - Token contract address
       * @param {string} account - Account address
       * @returns {Promise<Object>} Token balance message
       */
      getBalance: async (contractId, account) => {
        try {
          const result = await this._request('GET', `/v1/token/${contractId}/balance/${account}`);
          return this.sdk.messageSystem.createMessage('TOKEN_BALANCE', {
            contractId,
            account,
            balance: result.value
          });
        } catch (error) {
          return this.sdk.messageSystem.createErrorMessage('TOKEN_BALANCE_ERROR', error);
        }
      },

      /**
       * Get token info
       * @param {string} contractId - Token contract address
       * @returns {Promise<Object>} Token info message
       */
      getInfo: async (contractId) => {
        try {
          const result = await this._request('GET', `/v1/token/${contractId}/info`);
          return this.sdk.messageSystem.createMessage('TOKEN_INFO', {
            contractId,
            info: result
          });
        } catch (error) {
          return this.sdk.messageSystem.createErrorMessage('TOKEN_INFO_ERROR', error);
        }
      }
    };
  }

  /**
   * Contract-related API endpoints
   * @returns {Object} Contract API methods
   */
  contracts() {
    return {
      /**
       * Call a contract read method
       * @param {string} contractId - Contract address
       * @param {string} method - Method name
       * @param {Object} args - Method arguments
       * @returns {Promise<Object>} Contract call message
       */
      call: async (contractId, method, args = {}) => {
        try {
          let result;
          
          // For GET request with simple arguments
          if (Object.keys(args).length <= 3 && Object.values(args).every(v => typeof v === 'string')) {
            result = await this._request('GET', `/v1/contract/${contractId}/${method}`, null, args);
          } else {
            // For POST request with complex arguments
            result = await this._request('POST', `/v1/contract/${contractId}/${method}`, args);
          }
          
          return this.sdk.messageSystem.createMessage('CONTRACT_CALL', {
            contractId,
            method,
            args,
            result
          });
        } catch (error) {
          return this.sdk.messageSystem.createErrorMessage('CONTRACT_CALL_ERROR', error);
        }
      }
    };
  }
}

/**
 * Kondor wallet integration
 */
class KondorWallet {
  /**
   * Create a new KondorWallet
   * @param {OpenKAlphaSDK} sdk - Parent SDK instance
   */
  constructor(sdk) {
    this.sdk = sdk;
    
    // Generate wallet-specific storage key
    const domain = window.location.hostname || 'localhost';
    this.storageNamespace = `${domain}-kondor-wallet`;
    
    // Session data keys
    this.ADDRESS_KEY = `${this.storageNamespace}.address`;
    this.SESSION_KEY = `${this.storageNamespace}.session`;
    this.SESSION_TIMESTAMP_KEY = `${this.storageNamespace}.session_timestamp`;
    
    // Get stored address - only retrieve if persistent sessions are enabled
    this.address = this.sdk.options.persistentSession ? this._getStoredAddress() : null;
    
    // Check if Kondor is available
    this._checkKondorAvailability();
  }

  /**
   * Connect to Kondor wallet
   * @param {boolean} saveSession - Whether to save session for persistence
   * @returns {Promise<string>} Connected wallet address
   */
  async connect(saveSession = true) {
    try {
      // Check if Kondor is available
      if (!window.kondor) {
        throw this.sdk._createError('Kondor wallet not detected', {
          suggestion: 'Please install the Kondor wallet extension'
        });
      }

      // Add a timeout to the wallet connection
      const accounts = await this._promiseWithTimeout(
        window.kondor.getAccounts(),
        this.sdk.options.timeout,
        'Wallet connection timed out'
      );

      if (!Array.isArray(accounts) || accounts.length === 0) {
        throw this.sdk._createError('No accounts found in Kondor wallet', {
          suggestion: 'Make sure you have created an account in Kondor'
        });
      }

      // Get the first account address
      this.address = accounts[0].address;
      
      // Store session data if saving session
      if (saveSession) {
        // Store the session data with TTL
        this._storeSession(this.address, this.sdk.options.storageTTL);
      }
      
      // Send wallet connected message
      this.sdk.messageSystem.createMessage('WALLET_CONNECTED', {
        address: this.address
      });

      this.sdk._debug('Connected to wallet:', this.address);
      return this.address;
    } catch (error) {
      this.sdk._debug('Failed to connect to wallet:', error);
      
      // Provide more user-friendly error message
      let errorMessage = 'Failed to connect to wallet';
      
      if (error.message.includes('timeout')) {
        errorMessage = 'Connection to wallet timed out. Please try again.';
      } else if (error.message.includes('not detected')) {
        errorMessage = 'Kondor wallet extension not detected. Please install it.';
      }
      
      this.disconnect();
      
      // Send wallet connection error message
      this.sdk.messageSystem.createErrorMessage('WALLET_CONNECT_ERROR', 
        this.sdk._createError(errorMessage, { originalError: error })
      );
      
      throw this.sdk._createError(errorMessage, { originalError: error });
    }
  }
  
  /**
   * Validate and reconnect to a stored wallet session
   * @returns {Promise<string|null>} Connected wallet address or null if failed
   */
  async validateAndReconnect() {
    try {
      // Check if we have a stored session
      if (!this.address) {
        return null;
      }
      
      // Check if Kondor is available
      if (!window.kondor) {
        throw new Error('Kondor wallet not detected');
      }
      
      // Get accounts from Kondor
      const accounts = await window.kondor.getAccounts();
      
      // Validate that the stored address is in the accounts list
      const matchingAccount = accounts.find(acc => acc.address === this.address);
      
      if (!matchingAccount) {
        throw new Error('Stored wallet address no longer available');
      }
      
      // Send wallet connected message
      this.sdk.messageSystem.createMessage('WALLET_CONNECTED', {
        address: this.address,
        reconnected: true
      });
      
      this.sdk._debug('Reconnected to wallet:', this.address);
      return this.address;
    } catch (error) {
      this.sdk._debug('Failed to reconnect to wallet:', error);
      this.disconnect(true); // Clear the invalid session
      return null;
    }
  }

  /**
   * Disconnect from wallet
   * @param {boolean} clearSession - Whether to clear the stored session
   */
  disconnect(clearSession = true) {
    this.address = null;
    
    // Clear stored session if requested
    if (clearSession) {
      this._clearStoredSession();
    }
    
    // Send wallet disconnected message
    this.sdk.messageSystem.createMessage('WALLET_DISCONNECTED');
    
    this.sdk._debug('Disconnected from wallet');
  }

  /**
   * Check if wallet is connected
   * @returns {boolean} True if wallet is connected
   */
  isConnected() {
    return !!this.address;
  }

  /**
   * Get connected wallet address
   * @returns {string|null} Wallet address or null if not connected
   */
  getAddress() {
    return this.address;
  }

  /**
 * Get session expiry timestamp
 * @returns {number|null} Expiry timestamp or null if not available
 */
getSessionExpiry() {
    // First try to get the direct expiry time
    const expiryTime = this.sdk.secureStorage.getItem('session.expiryTime');
    if (expiryTime) {
      return expiryTime;
    }
    
    // Fall back to the session timestamp's expiry
    return this.sdk.secureStorage.getExpiry(this.SESSION_TIMESTAMP_KEY);
  }
  
  /**
   * Get stored wallet address
   * @returns {string|null} Stored wallet address or null
   */
  getStoredAddress() {
    return this._getStoredAddress();
  }

  /**
   * Helper method to add timeout to promises
   * @param {Promise} promise - Promise to add timeout to
   * @param {number} timeoutMs - Timeout in milliseconds
   * @param {string} errorMessage - Error message if timeout occurs
   * @returns {Promise} Promise with timeout
   * @private
   */
  async _promiseWithTimeout(promise, timeoutMs, errorMessage) {
    let timeoutHandle;
    const timeoutPromise = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => reject(new Error(errorMessage)), timeoutMs);
    });

    return Promise.race([
      promise,
      timeoutPromise
    ]).finally(() => {
      clearTimeout(timeoutHandle);
    });
  }

  /**
   * Store wallet session data securely with encryption and expiration
   * @param {string} address - Wallet address
   * @param {number} ttl - Optional custom time-to-live in milliseconds
   * @private
   */
  _storeSession(address, ttl) {
    try {
      // Generate a session token
      const sessionToken = this._generateSessionToken();
      
      // Store the address
      this.sdk.secureStorage.setItem(this.ADDRESS_KEY, address, ttl);
      
      // Store session token
      this.sdk.secureStorage.setItem(this.SESSION_KEY, sessionToken, ttl);
      
      // Store session timestamp
      this.sdk.secureStorage.setItem(this.SESSION_TIMESTAMP_KEY, Date.now(), ttl);
      
      this.sdk._debug('Wallet session stored securely with encryption and timeout');
    } catch (error) {
      this.sdk._debug('Error storing wallet session:', error);
    }
  }

  /**
   * Get stored wallet address from secure storage
   * @returns {string|null} Wallet address or null if not stored or expired
   * @private
   */
  _getStoredAddress() {
    try {
      const address = this.sdk.secureStorage.getItem(this.ADDRESS_KEY);
      if (address) {
        this.sdk._debug('Retrieved wallet address from secure storage');
      }
      return address;
    } catch (error) {
      this.sdk._debug('Error retrieving wallet address:', error);
      return null;
    }
  }

  /**
   * Clear stored wallet session
   * @private
   */
  _clearStoredSession() {
    try {
      this.sdk.secureStorage.removeItem(this.ADDRESS_KEY);
      this.sdk.secureStorage.removeItem(this.SESSION_KEY);
      this.sdk.secureStorage.removeItem(this.SESSION_TIMESTAMP_KEY);
      this.sdk._debug('Wallet session removed from secure storage');
    } catch (error) {
      this.sdk._debug('Error clearing wallet session:', error);
    }
  }
  
  /**
   * Generate a random session token
   * @returns {string} Random session token
   * @private
   */
  _generateSessionToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 32; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
  }

  /**
   * Check if Kondor is available and log status
   * @private
   */
  _checkKondorAvailability() {
    const isAvailable = typeof window.kondor !== 'undefined';
    this.sdk._debug(`Kondor wallet ${isAvailable ? 'is' : 'is not'} available`);
    
    // Safe wallet detection message - make sure messageSystem exists first
    const sendDetectionMessage = () => {
      if (this.sdk.messageSystem) {
        this.sdk.messageSystem.createMessage('WALLET_DETECTED', {
          type: 'kondor'
        });
      }
    };
    
    if (!isAvailable) {
      // Set up polling to check for Kondor
      const checkInterval = setInterval(() => {
        if (typeof window.kondor !== 'undefined') {
          this.sdk._debug('Kondor wallet detected');
          sendDetectionMessage();
          clearInterval(checkInterval);
        }
      }, 1000);
      
      // Clear interval after 10 seconds to avoid indefinite polling
      setTimeout(() => clearInterval(checkInterval), 10000);
    } else {
      // Use setTimeout to ensure messageSystem is initialized when this runs
      setTimeout(sendDetectionMessage, 0);
    }
  }
}

// Export the main class to global scope
window.OpenKAlphaSDK = OpenKAlphaSDK;

// CommonJS export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = OpenKAlphaSDK;
}