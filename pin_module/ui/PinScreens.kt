package com.suraksha.security.ui

import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.flow.collectLatest
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
// Add more imports as needed

/**
 * Main Setup Screen for PIN.
 * Shows only on first setup.
 */
@Composable
fun SetPinScreen(
    viewModel: PinViewModel = viewModel(),
    onPinSetSuccess: () -> Unit
) {
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var step by remember { mutableStateOf(1) } // 1: Enter PIN, 2: Confirm PIN
    
    // UI State from ViewModel
    val errorState by viewModel.errorState.collectAsState()
    
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = if (step == 1) "Create a New PIN" else "Confirm your PIN",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        // Display dots for PIN
        PinIndicator(length = if (step == 1) pin.length else confirmPin.length)
        
        if (errorState != null) {
            Text(text = errorState!!, color = Color.Red, modifier = Modifier.padding(top = 8.dp))
        }

        Spacer(modifier = Modifier.height(32.dp))

        PinKeypad(
            onDigitClick = { digit ->
                if (step == 1) {
                    if (pin.length < 6) pin += digit
                } else {
                    if (confirmPin.length < 6) confirmPin += digit
                }
            },
            onBackspaceClick = {
                if (step == 1) {
                    if (pin.isNotEmpty()) pin = pin.dropLast(1)
                } else {
                    if (confirmPin.isNotEmpty()) confirmPin = confirmPin.dropLast(1)
                }
            }
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = {
                if (step == 1) {
                    if (pin.length >= 4) {
                        step = 2
                        // Clear view model state if reusing it, but here we use local state for creation flow
                    }
                } else {
                    if (pin == confirmPin) {
                        viewModel.setPin(pin) // Expose setPin in ViewModel to call manager
                        onPinSetSuccess()
                    } else {
                        // Show error "PINs do not match"
                    }
                }
            },
            enabled = (step == 1 && pin.length >= 4) || (step == 2 && confirmPin.length >= 4)
        ) {
            Text(if (step == 1) "Next" else "Confirm")
        }
    }
}

@Composable
fun UnlockPinScreen(
    activity: FragmentActivity,
    viewModel: PinViewModel = viewModel(),
    onUnlockSuccess: () -> Unit,
    onForceLogout: () -> Unit
) {
    val pin by viewModel.pinState.collectAsState()
    val error by viewModel.errorState.collectAsState()
    
    LaunchedEffect(Unit) {
        viewModel.checkBiometric(activity, onUnlockSuccess)
    }

    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
         Text("Enter PIN to Unlock", style = MaterialTheme.typography.titleLarge)
         
         Spacer(modifier = Modifier.height(32.dp))
         
         PinIndicator(length = pin.length)
         
         if (error != null) {
             Text(error!!, color = MaterialTheme.colorScheme.error)
         }
         
         Spacer(modifier = Modifier.height(32.dp))
         
         PinKeypad(
             onDigitClick = { viewModel.onPinDigitClick(it) },
             onBackspaceClick = { viewModel.onBackspaceClick() }
         )
         
         Button(
             onClick = { viewModel.verifyPinForUnlock(onUnlockSuccess, onForceLogout) },
             modifier = Modifier.padding(top = 24.dp)
         ) {
             Text("Unlock")
         }
    }
}

@Composable
fun PinIndicator(length: Int) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        repeat(6) { index ->
            val filled = index < length
            Box(
                modifier = Modifier
                    .size(16.dp)
                    .background(
                        if (filled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
                        shape = MaterialTheme.shapes.small
                    ) // simplified dot
            )
        }
    }
}

@Composable
fun PinKeypad(onDigitClick: (String) -> Unit, onBackspaceClick: () -> Unit) {
    val keys = listOf("1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "DEL")
    
    LazyVerticalGrid(
        columns = GridCells.Fixed(3),
        modifier = Modifier.width(280.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        items(keys) { key ->
            if (key == "DEL") {
                Button(onClick = onBackspaceClick) {
                    Text("⌫")
                }
            } else if (key.isNotEmpty()) {
                Button(onClick = { onDigitClick(key) }) {
                   Text(key, fontSize = 24.sp)
                }
            } else {
                Spacer(modifier = Modifier.size(48.dp)) // empty slot for alignment
            }
        }
    }
}
