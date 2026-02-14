package com.suraksha.security

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.TimeUnit

/**
 * Manages PIN security, storage, and validation.
 * Uses EncryptedSharedPreferences for secure storage.
 * Implements lockout logic after 5 failed attempts.
 */
class PinManager(context: Context) {

    private val sharedPreferences: SharedPreferences

    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        sharedPreferences = EncryptedSharedPreferences.create(
            context,
            "secure_pin_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private val _isLockedOut = MutableStateFlow(false)
    val isLockedOut: StateFlow<Boolean> = _isLockedOut.asStateFlow()

    private val _lockoutTimeRemaining = MutableStateFlow(0L)
    val lockoutTimeRemaining: StateFlow<Long> = _lockoutTimeRemaining.asStateFlow()

    companion object {
        private const val KEY_PIN_HASH = "pin_hash"
        private const val KEY_PIN_SALT = "pin_salt"
        private const val KEY_ATTEMPT_COUNT = "attempt_count"
        private const val KEY_LOCKOUT_TIMESTAMP = "lockout_timestamp"
        private const val MAX_ATTEMPTS = 5
        private const val LOCKOUT_DURATION_MS = 30000L // 30 seconds
    }

    fun isPinSet(): Boolean {
        return sharedPreferences.contains(KEY_PIN_HASH)
    }

    /**
     * Sets a new PIN.
     * @param pin The raw PIN string (4-6 digits).
     */
    fun setPin(pin: String) {
        val salt = generateSalt()
        val hash = hashPin(pin, salt)

        sharedPreferences.edit()
            .putString(KEY_PIN_HASH, hash)
            .putString(KEY_PIN_SALT, Base64.encodeToString(salt, Base64.DEFAULT))
            .putInt(KEY_ATTEMPT_COUNT, 0)
            .putLong(KEY_LOCKOUT_TIMESTAMP, 0)
            .apply()
    }

    /**
     * Verifies the entered PIN.
     * @param enteredPin The raw PIN string to verify.
     * @return True if PIN is correct, False otherwise.
     */
    fun verifyPin(enteredPin: String): Boolean {
        if (isLockedOut()) return false

        val storedHash = sharedPreferences.getString(KEY_PIN_HASH, null)
        val storedSaltStr = sharedPreferences.getString(KEY_PIN_SALT, null)

        if (storedHash == null || storedSaltStr == null) return false

        val salt = Base64.decode(storedSaltStr, Base64.DEFAULT)
        val enteredHash = hashPin(enteredPin, salt)

        if (enteredHash == storedHash) {
            resetAttempts()
            return true
        } else {
            incrementAttempts()
            return false
        }
    }

    fun clear() {
        sharedPreferences.edit().clear().apply()
    }
    
    fun getRemainingAttempts(): Int {
        val currentAttempts = sharedPreferences.getInt(KEY_ATTEMPT_COUNT, 0)
        return if (MAX_ATTEMPTS - currentAttempts < 0) 0 else MAX_ATTEMPTS - currentAttempts
    }

    private fun generateSalt(): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(16)
        random.nextBytes(salt)
        return salt
    }

    private fun hashPin(pin: String, salt: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt)
        val hashedBytes = md.digest(pin.toByteArray())
        return Base64.encodeToString(hashedBytes, Base64.DEFAULT)
    }

    private fun incrementAttempts() {
        var attempts = sharedPreferences.getInt(KEY_ATTEMPT_COUNT, 0)
        attempts++
        
        val editor = sharedPreferences.edit()
        editor.putInt(KEY_ATTEMPT_COUNT, attempts)
        
        if (attempts >= MAX_ATTEMPTS) {
           val lockoutTime = System.currentTimeMillis() + LOCKOUT_DURATION_MS
           editor.putLong(KEY_LOCKOUT_TIMESTAMP, lockoutTime)
           _isLockedOut.value = true
           // In a real app, you might start a countdown timer here to update _lockoutTimeRemaining 
           // and reset _isLockedOut after time expires.
        }
        editor.apply()
    }

    private fun resetAttempts() {
        sharedPreferences.edit()
            .putInt(KEY_ATTEMPT_COUNT, 0)
            .putLong(KEY_LOCKOUT_TIMESTAMP, 0)
            .apply()
        _isLockedOut.value = false
    }

    private fun isLockedOut(): Boolean {
        val lockoutTimestamp = sharedPreferences.getLong(KEY_LOCKOUT_TIMESTAMP, 0)
        if (lockoutTimestamp == 0L) return false

        val currentTime = System.currentTimeMillis()
        if (currentTime > lockoutTimestamp) {
            // Lockout expired
            resetAttempts()
            return false
        }
        _isLockedOut.value = true
        return true
    }
}
