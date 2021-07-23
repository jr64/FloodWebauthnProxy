$(document).ready(function () {

    // check whether current browser supports WebAuthn
    if (!window.PublicKeyCredential) {
        alert("Error: this browser does not support WebAuthn");
        return;
    }

    //document.getElementById('sign-in-form').onsubmit = loginUser;
    $("#sign-in-form").on("submit", onBeginLogin)
    $("#register-form").on("submit", onBeginRegistration)
});

function onBeginRegistration() {
    
    username = encodeURI($("#user").val())
  
    hideSuccess()

    if (username === "") {
        showError("Please enter a username");
        return false;
    }

    hideError()

    $.post('/webauthn/register/begin/' + username, null, function (data) { return data }, 'json').then(onRegistrationCredentialRequestOptionsReceived, onGenericError)
       
    return false;

}
function onBeginLogin() {

    username = encodeURI($("#user").val())

    if (username === "") {
        showError("Please enter a username");
        return false;
    }

    hideError()

    $.post('/webauthn/login/begin/' + username, null, function (data) { return data }, 'json').then(onCredentialRequestOptionsReceived, onGenericError)

    return false;
}

function onRegistrationCredentialRequestOptionsReceived(credentialCreationOptions) {
    console.log(credentialCreationOptions)

    credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
    credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);

    if (credentialCreationOptions.publicKey.excludeCredentials) {
        for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
            credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
        }
    }

    return navigator.credentials.create({
        publicKey: credentialCreationOptions.publicKey
    }).then(onRegistrationCredentialsReceived, (err) => {
        onGenericError({message: err.message})
    })
}

function onCredentialRequestOptionsReceived(credentialRequestOptions) {
    console.log(credentialRequestOptions)

    credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
    credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
        listItem.id = bufferDecode(listItem.id)
    });

    navigator.credentials.get({
        publicKey: credentialRequestOptions.publicKey
    }).then(onCredentialsReceived, (err) => {
        console.log(err)
        onGenericError({message: "Authentication canceled, timed out or failed."})
    })
}

function onRegistrationCredentialsReceived(credential) {
    console.log(credential)

    var jsonRequest = JSON.stringify({
        id: credential.id,
        rawId: bufferEncode(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: bufferEncode(credential.response.attestationObject),
            clientDataJSON: bufferEncode(credential.response.clientDataJSON),
        },
    });

    $.post('/webauthn/register/finish/' + username, jsonRequest, function (data) { return data },'json')
    .then((success) => {
        showSuccessHtml("Registration successful, <a href=\"/webauthn/\">click here to sign in.</a>")
    }, onGenericError)
}
function onCredentialsReceived(credentials) {
    console.log(credentials)

    var jsonReq = JSON.stringify({
        id: credentials.id,
        rawId: bufferEncode(credentials.rawId),
        type: credentials.type,
        response: {
            authenticatorData: bufferEncode(credentials.response.authenticatorData),
            clientDataJSON: bufferEncode(credentials.response.clientDataJSON),
            signature: bufferEncode(credentials.response.signature),
            userHandle: bufferEncode(credentials.response.userHandle),
        },
    })
    $.post('/webauthn/login/finish/' + username, jsonReq, function (data) { return data }, 'json')
        .then((success) => {
            document.location.replace("/")
            return
        }, onGenericError)
}


// Base64 to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");;
}

function onGenericError(msg) {
    console.log(msg)
    if (msg.responseJSON) {
        msg = msg.responseJSON;
    }
    if(msg.message) {
        showError(msg.message)
    }else{
        showError(msg)
    }
}
function showError(text) {
    $('#error-message').text(text).show()
}

function hideError(){
    $('#error-message').hide()
}

function showSuccessHtml(text) {
    $('#success-message').html(text)
    $('#success-message').show()
}

function hideSuccess(){
    $('#success-message').hide()
}
