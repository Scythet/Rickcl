import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException

data class DeviceCodeInfo(
    val deviceCode: String,
    val userCode: String,
    val verificationUri: String,
    val interval: Int,
    val expiresIn: Int
)

sealed class PollStatus {
    data class Pending(val message: String) : PollStatus()
    data class Done(val result: AuthResult) : PollStatus()
}

sealed class AuthResult {
    data class Success(val mcToken: String, val profile: JSONObject) : AuthResult()
    data class Error(val message: String) : AuthResult()
}

class MicrosoftAuth(private val clientId: String = "0000000044cc169b") {
    private val client = OkHttpClient()

    suspend fun requestDeviceCode(): DeviceCodeInfo = withContext(Dispatchers.IO) {
        val body = FormBody.Builder()
            .add("client_id", clientId)
            .add("scope", "XboxLive.signin offline_access")
            .build()

        val request = Request.Builder()
            .url("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .post(body)
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string() ?: throw IOException("Respuesta vacía")
            val json = JSONObject(responseBody)
            if (!response.isSuccessful) {
                throw IOException(json.optString("error_description", "Error solicitando código: $responseBody"))
            }
            DeviceCodeInfo(
                deviceCode = json.getString("device_code"),
                userCode = json.getString("user_code"),
                verificationUri = json.getString("verification_uri"),
                interval = json.optInt("interval", 5),
                expiresIn = json.optInt("expires_in", 900)
            )
        }
    }

    suspend fun pollAccessToken(
        deviceCode: String,
        interval: Int,
        onStatus: (PollStatus) -> Unit
    ): AuthResult = withContext(Dispatchers.IO) {
        val intervalMs = (interval * 1000L).coerceAtLeast(5000L)
        val grantType = "urn:ietf:params:oauth:grant-type:device_code"

        while (true) {
            delay(intervalMs)

            val body = FormBody.Builder()
                .add("client_id", clientId)
                .add("device_code", deviceCode)
                .add("grant_type", grantType)
                .build()

            val request = Request.Builder()
                .url("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .post(body)
                .build()

            val (payload, ok) = withContext(Dispatchers.IO) {
                client.newCall(request).execute().use { resp ->
                    val text = resp.body?.string() ?: "{}"
                    JSONObject(text) to resp.isSuccessful
                }
            }

            if (ok) {
                val msAccessToken = payload.getString("access_token")
                try {
                    val mcToken = authenticateMinecraftChain(msAccessToken)
                    val profile = fetchProfile(mcToken)
                    val result = AuthResult.Success(mcToken, profile)
                    onStatus(PollStatus.Done(result))
                    return@withContext result
                } catch (e: Exception) {
                    val errResult = AuthResult.Error(e.message ?: "Error en la cadena de autenticación")
                    onStatus(PollStatus.Done(errResult))
                    return@withContext errResult
                }
            } else {
                val error = payload.optString("error")
                when (error) {
                    "authorization_pending" -> {
                        onStatus(PollStatus.Pending("Esperando a que el usuario autorice..."))
                    }
                    "slow_down" -> {
                        delay(5000)
                    }
                    "expired_token" -> {
                        val errResult = AuthResult.Error("El código de dispositivo ha expirado.")
                        onStatus(PollStatus.Done(errResult))
                        return@withContext errResult
                    }
                    else -> {
                        val desc = payload.optString("error_description", "Error desconocido")
                        val errResult = AuthResult.Error(desc)
                        onStatus(PollStatus.Done(errResult))
                        return@withContext errResult
                    }
                }
            }
        }
    }

    private suspend fun authenticateMinecraftChain(msAccessToken: String): String = withContext(Dispatchers.IO) {
        val xblBody = JSONObject().apply {
            put("Properties", JSONObject().apply {
                put("AuthMethod", "RPS")
                put("SiteName", "user.auth.xboxlive.com")
                put("RpsTicket", msAccessToken)
            })
            put("RelyingParty", "http://auth.xboxlive.com")
            put("TokenType", "JWT")
        }
        val xblResp = postJson("https://user.auth.xboxlive.com/user/authenticate", xblBody)
        val xblToken = xblResp.getString("Token")
        val userHash = xblResp.getJSONObject("DisplayClaims").getJSONArray("xui").getJSONObject(0).getString("uhs")

        val xstsBody = JSONObject().apply {
            put("Properties", JSONObject().apply {
                put("SandboxId", "RETAIL")
                put("UserTokens", JSONArray().put(xblToken))
            })
            put("RelyingParty", "rp://api.minecraftservices.com/")
            put("TokenType", "JWT")
        }
        val (xstsOk, xstsResp) = postJsonRaw("https://xsts.auth.xboxlive.com/xsts/authorize", xstsBody)
        if (!xstsOk) {
            val err = xstsResp.optJSONObject("XErr") ?: xstsResp
            val code = err.optInt("XErr", 0)
            val msg = when (code) {
                2148916233 -> "La cuenta no tiene una cuenta Xbox asociada o es menor de edad sin verificar."
                2148916238 -> "La cuenta es infantil y requiere unirse a una familia de Microsoft."
                else -> xstsResp.optString("Message", "Error en XSTS: $xstsResp")
            }
            throw IOException(msg)
        }
        val xstsToken = xstsResp.getString("Token")

        val mcBody = JSONObject().apply {
            put("identityToken", "XBL3.0 x=$userHash;$xstsToken")
        }
        val mcResp = postJson("https://api.minecraftservices.com/authentication/login_with_xbox", mcBody)
        return@withContext mcResp.getString("access_token")
    }

    private suspend fun fetchProfile(mcAccessToken: String): JSONObject = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("https://api.minecraftservices.com/minecraft/profile")
            .header("Authorization", "Bearer $mcAccessToken")
            .header("Accept", "application/json")
            .get()
            .build()

        client.newCall(request).execute().use { resp ->
            val text = resp.body?.string() ?: "{}"
            val profileJson = JSONObject(text)
            if (!resp.isSuccessful) {
                throw IOException(profileJson.optString("errorDescription", "Error obteniendo perfil de Minecraft"))
            }
            return@withContext profileJson
        }
    }

    private fun postJson(url: String, body: JSONObject): JSONObject {
        val (ok, json) = postJsonRaw(url, body)
        if (!ok) throw IOException("Error en POST $url: $json")
        return json
    }

    private fun postJsonRaw(url: String, body: JSONObject): Pair<Boolean, JSONObject> {
        val mediaType = "application/json; charset=utf-8".toMediaType()
        val request = Request.Builder()
            .url(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .post(body.toString().toRequestBody(mediaType))
            .build()

        client.newCall(request).execute().use { response ->
            val text = response.body?.string()?.takeIf { it.isNotBlank() } ?: "{}"
            return response.isSuccessful to JSONObject(text)
        }
    }
}

