package com.rickcl.msauth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

object MicrosoftAuth {

    private const val CLIENT_ID = "7db897c2-7229-4612-9003-2be8f81b6436"

    private const val SCOPE = "XboxLive.signin offline_access"

    private val client = OkHttpClient()

    data class DeviceCodeInfo(
        val deviceCode: String,
        val userCode: String,
        val verificationUri: String,
        val expiresIn: Int,
        val interval: Int
    )

    data class MinecraftProfile(
        val uuid: String,
        val username: String,
        val skinUrl: String?
    )

    sealed class AuthResult {
        data class Success(val profile: MinecraftProfile, val accessToken: String) : AuthResult()
        data class Error(val message: String) : AuthResult()
    }

    sealed class PollStatus {
        object Pending : PollStatus()
        data class Done(val result: AuthResult) : PollStatus()
    }

    suspend fun requestDeviceCode(): DeviceCodeInfo = withContext(Dispatchers.IO) {
        val body = FormBody.Builder()
            .add("client_id", CLIENT_ID)
            .add("scope", SCOPE)
            .build()

        val request = Request.Builder()
            .url("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode")
            .post(body)
            .build()

        client.newCall(request).execute().use { response ->
            val json = JSONObject(response.body?.string() ?: throw IOException("Respuesta vacía"))
            if (!response.isSuccessful) {
                throw IOException(json.optString("error_description", "Error solicitando código"))
            }
            DeviceCodeInfo(
                deviceCode = json.getString("device_code"),
                userCode = json.getString("user_code"),
                verificationUri = json.getString("verification_uri"),
                expiresIn = json.getInt("expires_in"),
                interval = json.optInt("interval", 5)
            )
        }
    }

    suspend fun pollForToken(
        deviceCode: DeviceCodeInfo,
        onStatus: (PollStatus) -> Unit
    ) {
        val deadline = System.currentTimeMillis() + deviceCode.expiresIn * 1000L
        var intervalMs = deviceCode.interval * 1000L

        while (System.currentTimeMillis() < deadline) {
            delay(intervalMs)

            val body = FormBody.Builder()
                .add("client_id", CLIENT_ID)
                .add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .add("device_code", deviceCode.deviceCode)
                .build()

            val request = Request.Builder()
                .url("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                .post(body)
                .build()

            val json = withContext(Dispatchers.IO) {
                client.newCall(request).execute().use { resp ->
                    JSONObject(resp.body?.string() ?: "{}") to resp.isSuccessful
                }
            }

            val (payload, ok) = json

            if (ok) {
                val msAccessToken = payload.getString("access_token")
                val result = try {
                    finishXboxAndMinecraftLogin(msAccessToken)
                } catch (e: Throwable) {
                    AuthResult.Error(e.message ?: (e.javaClass.simpleName + " talking to Xbox Live"))
                }
                onStatus(PollStatus.Done(result))
                return
            } else {
                when (payload.optString("error")) {
                    "authorization_pending" -> onStatus(PollStatus.Pending)
                    "slow_down" -> intervalMs += 5000
                    "expired_token" -> {
                        onStatus(PollStatus.Done(AuthResult.Error("El código expiró, pide uno nuevo")))
                        return
                    }
                    "authorization_declined" -> {
                        onStatus(PollStatus.Done(AuthResult.Error("Inicio de sesión rechazado")))
                        return
                    }
                    else -> {
                        onStatus(PollStatus.Done(AuthResult.Error(payload.optString("error_description", "Error desconocido"))))
                        return
                    }
                }
            }
        }
        onStatus(PollStatus.Done(AuthResult.Error("Tiempo agotado esperando el login")))
    }

    private suspend fun finishXboxAndMinecraftLogin(msAccessToken: String): AuthResult =
        withContext(Dispatchers.IO) {
            val xblBody = JSONObject().apply {
                put("Properties", JSONObject().apply {
                    put("AuthMethod", "RPS")
                    put("SiteName", "user.auth.xboxlive.com")
                    put("RpsTicket", "d=$msAccessToken")
                })
                put("RelyingParty", "http://auth.xboxlive.com")
                put("TokenType", "JWT")
            }
            val xblJson = postJson("https://user.auth.xboxlive.com/user/authenticate", xblBody)
            val xblToken = xblJson.getString("Token")
            val userHash = xblJson.getJSONObject("DisplayClaims")
                .getJSONArray("xui").getJSONObject(0).getString("uhs")

            val xstsBody = JSONObject().apply {
                put("Properties", JSONObject().apply {
                    put("SandboxId", "RETAIL")
                    put("UserTokens", org.json.JSONArray().put(xblToken))
                })
                put("RelyingParty", "rp://api.minecraftservices.com/")
                put("TokenType", "JWT")
            }
            val xstsResponse = postJsonRaw("https://xsts.auth.xboxlive.com/xsts/authorize", xstsBody)
            if (!xstsResponse.first) {
                val err = xstsResponse.second
                val code = err.optInt("XErr", 0)
                val msg = when (code) {
                    2148916233 -> "Esta cuenta de Microsoft no tiene un perfil Xbox. Créalo en xbox.com."
                    2148916238 -> "Esta cuenta es de un menor de edad y necesita estar en un grupo familiar."
                    else -> "Xbox Live rechazó la sesión (XErr $code)"
                }
                return@withContext AuthResult.Error(msg)
            }
            val xstsJson = xstsResponse.second
            val xstsToken = xstsJson.getString("Token")

            val mcBody = JSONObject().apply {
                put("identityToken", "XBL3.0 x=$userHash;$xstsToken")
            }
            val mcJson = postJson("https://api.minecraftservices.com/authentication/login_with_xbox", mcBody)
            val mcAccessToken = mcJson.getString("access_token")

            val profileRequest = Request.Builder()
                .url("https://api.minecraftservices.com/minecraft/profile")
                .header("Authorization", "Bearer $mcAccessToken")
                .get()
                .build()

            client.newCall(profileRequest).execute().use { resp ->
                val profileJson = JSONObject(resp.body?.string() ?: "{}")
                if (!resp.isSuccessful) {
                    val msg = if (resp.code == 404) {
                        "Esta cuenta no ha comprado Minecraft (no tiene perfil de Java/Bedrock)."
                    } else {
                        profileJson.optString("errorMessage", "Error obteniendo el perfil")
                    }
                    return@withContext AuthResult.Error(msg)
                }
                val skinUrl = profileJson.optJSONArray("skins")
                    ?.optJSONObject(0)?.optString("url")

                AuthResult.Success(
                    profile = MinecraftProfile(
                        uuid = profileJson.getString("id"),
                        username = profileJson.getString("name"),
                        skinUrl = skinUrl
                    ),
                    accessToken = mcAccessToken
                )
            }
        }

    private fun postJson(url: String, body: JSONObject): JSONObject {
        val (ok, json) = postJsonRaw(url, body)
        if (!ok) throw IOException(json.toString())
        return json
    }

    private fun postJsonRaw(url: String, body: JSONObject): Pair<Boolean, JSONObject> {
        val mediaType = "application/json; charset=utf-8".toMediaType()
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .post(body.toString().toRequestBody(mediaType))
            .build()

        client.newCall(request).execute().use { response ->
            val text = response.body?.string()?.takeIf { it.isNotBlank() } ?: "{}"
            return response.isSuccessful to JSONObject(text)
        }
    }
}
