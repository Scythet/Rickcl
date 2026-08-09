var exec = require('cordova/exec');

var MSAuth = {
    /**
     * Inicia el login real. onEvent recibe varios mensajes en el tiempo:
     *   { type: 'code', userCode, verificationUri }  -> mostrar el código
     *   { type: 'pending' }                          -> seguir esperando
     *   { type: 'success', uuid, username, skinUrl }  -> login OK
     *   { type: 'error', message }                    -> falló
     */
    startLogin: function (onEvent) {
        exec(onEvent, function (err) {
            onEvent({ type: 'error', message: String(err) });
        }, 'MSAuth', 'startLogin', []);
    },

    /** Abre microsoft.com/link en el navegador del sistema con el código ya listo */
    openVerificationUrl: function () {
        exec(null, null, 'MSAuth', 'openVerificationUrl', []);
    }
};

module.exports = MSAuth;
