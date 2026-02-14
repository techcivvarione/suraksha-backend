package com.suraksha.security.ui

import android.app.Application
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.suraksha.security.BiometricHelper
import com.suraksha.security.PinManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class PinViewModel(application: Application) : AndroidViewModel(application) {

    private val pinManager = PinManager(application)
    private val biometricHelper = BiometricHelper(application)

    private val _pinState = MutableStateFlow("")
    val pinState: StateFlow<String> = _pinState.asStateFlow()

    private val _errorState = MutableStateFlow<String?>(null)
    val errorState: StateFlow<String?> = _errorState.asStateFlow()
    
    private val _shakeTrigger = MutableStateFlow(0L)
    val shakeTrigger: StateFlow<Long> = _shakeTrigger.asStateFlow()
    
    private val _attemptsRemaining = MutableStateFlow(5)
    val attemptsRemaining: StateFlow<Int> = _attemptsRemaining.asStateFlow()

    // For "Change PIN" flow
    private val _isOldPinVerified = MutableStateFlow(false)
    val isOldPinVerified: StateFlow<Boolean> = _isOldPinVerified.asStateFlow()

    init {
        updateAttempts()
    }

    fun onPinDigitClick(digit: String) {
        if (_pinState.value.length < 6) {
            _pinState.value += digit
            _errorState.value = null // Clear error on new input
        }
    }

    fun onBackspaceClick() {
        if (_pinState.value.isNotEmpty()) {
            _pinState.value = _pinState.value.dropLast(1)
            _errorState.value = null
        }
    }

    fun clearPin() {
        _pinState.value = ""
        _errorState.value = null
    }
    
    fun createPin() {
        val pin = _pinState.value
        if (pin.length in 4..6) {
            pinManager.setPin(pin)
            // Navigate to next screen or confirm (Navigation logic handled by UI layer)
            clearPin()
        } else {
             _errorState.value = "PIN must be 4-6 digits"
             triggerShake()
        }
    }

    fun verifyPinForUnlock(onSuccess: () -> Unit, onForceLogout: () -> Unit) {
        val pin = _pinState.value
        if (pinManager.verifyPin(pin)) {
            clearPin()
            onSuccess()
        } else {
             _errorState.value = "Incorrect PIN"
             triggerShake()
             updateAttempts()
             clearPin()
             if (pinManager.getRemainingAttempts() == 0) {
                 // Check logic for lockout vs force logout. Requirement says force logout after 5 failures.
                 onForceLogout() 
             }
        }
    }
    
    // Change PIN Flow
    fun verifyOldPin(onSuccess:() -> Unit) {
         val pin = _pinState.value
        if (pinManager.verifyPin(pin)) {
            _isOldPinVerified.value = true
            clearPin()
            onSuccess()
        } else {
             _errorState.value = "Incorrect PIN"
             triggerShake()
             clearPin()
        }
    }
    
    fun updateNewPin(onSuccess:() -> Unit) {
        // Here we would typically have a confirm step. internal state management for brevity.
        // Assuming the UI handles the "Confirm" step by checking equality of two inputs or internal Flow.
        // simplified generic set:
         val pin = _pinState.value
        if (pin.length in 4..6) {
            pinManager.setPin(pin)
            onSuccess()
            clearPin()
            _isOldPinVerified.value = false // reset
        } else {
             _errorState.value = "PIN must be 4-6 digits"
             triggerShake()
        }
    }

    fun checkBiometric(activity: FragmentActivity, onSuccess: () -> Unit) {
        if (biometricHelper.isBiometricAvailable() && pinManager.isPinSet()) {
            biometricHelper.authenticate(activity, onSuccess, 
            onError = { _errorState.value = it },
            onFail = { _errorState.value = "Biometric failed" })
        }
    }
    
    fun isPinSet(): Boolean = pinManager.isPinSet()

    private fun updateAttempts() {
        _attemptsRemaining.value = pinManager.getRemainingAttempts()
    }
    
    private fun triggerShake() {
        _shakeTrigger.value = System.currentTimeMillis()
    }
}
