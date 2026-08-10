package com.rickcl.msauth

import android.content.Intent
import android.net.Uri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.apache.cordova.CallbackContext
import org.apache.cordova.CordovaPlugin
import org.apache.cordova.PluginResult
import org.json.JSONArray
import org.json.JSONObject

class MSAuthPlugin : CordovaPlugin() {

    private val scope = CoroutineScope(Dispatchers.Main)
    private var pendingDeviceCode: MicrosoftAuth.DeviceCodeInfo? = null

    override fun execute(
        action: String,
        args: JSONArray,
        callbackContext: CallbackContext
    ): Boolean {
        when (action) {
            "startLogin" -> {
                startLoginDEBUG(callbackContext)
                return true
            }
            "openVerificationUrl" -> {
                openVerificationUrl()
                return true
            }
            else -> return false
        }
    }

    private fun startLoginDEBUG(callbackContext: CallbackContext) {
        scope.launch {
            delay(1000)
            val codeJson = JSONObject().apply {
                put("type", "code")
                put("userCode", "TEST-1234")
                put("verificationUri", "https://microsoft.com/link")
            }
            val codeResult = PluginResult(PluginResult.Status.OK, codeJson)
            codeResult.keepCallback = true
            callbackContext.sendPluginResult(codeResult)

            delay(2000)
            val doneJson = JSONObject().apply {
                put("type", "success")
                put("uuid", "debug-uuid")
                put("username", "DebugBridgeWorks")
                put("skinUrl", JSONObject.NULL)
            }
            callbackContext.sendPluginResult(PluginResult(PluginResult.Status.OK, doneJson))
        }
    }

    private fun openVerificationUrl() {
        val url = pendingDeviceCode?.verificationUri ?: "https://microsoft.com/link"
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        cordova.context.startActivity(intent)
    }
}
