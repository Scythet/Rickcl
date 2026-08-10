package com.rickcl.msauth

import android.content.Intent
import android.net.Uri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
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
                startLogin(callbackContext)
                return true
            }
            "openVerificationUrl" -> {
                openVerificationUrl()
                return true
            }
            else -> return false
        }
    }

    private fun startLogin(callbackContext: CallbackContext) {
        scope.launch {
            try {
                val deviceCode = MicrosoftAuth.requestDeviceCode()
                pendingDeviceCode = deviceCode

                val codeJson = JSONObject().apply {
                    put("type", "code")
                    put("userCode", deviceCode.userCode)
                    put("verificationUri", deviceCode.verificationUri)
                }
                val codeResult = PluginResult(PluginResult.Status.OK, codeJson)
                codeResult.keepCallback = true
                callbackContext.sendPluginResult(codeResult)

                MicrosoftAuth.pollForToken(deviceCode) { status ->
                    when (status) {
                        is MicrosoftAuth.PollStatus.Pending -> {
                            val pendingJson = JSONObject().apply { put("type", "pending") }
                            val r = PluginResult(PluginResult.Status.OK, pendingJson)
                            r.keepCallback = true
                            callbackContext.sendPluginResult(r)
                        }
                        is MicrosoftAuth.PollStatus.Done -> {
                            when (val result = status.result) {
                                is MicrosoftAuth.AuthResult.Success -> {
                                    val doneJson = JSONObject().apply {
                                        put("type", "success")
                                        put("uuid", result.profile.uuid)
                                        put("username", result.profile.username)
                                        put("skinUrl", result.profile.skinUrl ?: JSONObject.NULL)
                                    }
                                    callbackContext.sendPluginResult(
                                        PluginResult(PluginResult.Status.OK, doneJson)
                                    )
                                }
                                is MicrosoftAuth.AuthResult.Error -> {
                                    val errJson = JSONObject().apply {
                                        put("type", "error")
                                        put("message", result.message)
                                    }
                                    callbackContext.sendPluginResult(
                                        PluginResult(PluginResult.Status.OK, errJson)
                                    )
                                }
                            }
                        }
                    }
                }
            } catch (e: Throwable) {
                val errJson = JSONObject().apply {
                    put("type", "error")
                    put("message", e.message ?: (e.javaClass.simpleName + " during login"))
                }
                callbackContext.se
