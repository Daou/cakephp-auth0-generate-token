<?php

namespace Daou\Auth0GenerateToken;
use Auth0\SDK\Auth0;

class Token extends Auth0 {

    /**
     * Exchanges the code from the URI parameters for an access token, id token
     * @return Boolean Whether it exchanged the code or not correctly
     */
    public function generate() {
        if (!isset($_REQUEST['code'])) {
            return false;
        }
        $code = $_REQUEST['code'];

        $this->debugInfo("Code: ".$code);

        // Generate the url to the API that will give us the access token and id token
        $auth_url = $this->generateUrl('token');
        // Make the call
        $response = $this->oauth_client->getAccessToken($auth_url, "authorization_code", array(
            "code" => $code,
            "redirect_uri" => $this->redirect_uri
        ), array(
            'Auth0-Client' => ApiClient::getInfoHeadersData()->build()
        ));

        $auth0_response = $response['result'];

        if ($response['code'] !== 200) {
            throw new ApiException($auth0_response['error'] . ': '. $auth0_response['error_description']);
        }

        $this->debugInfo(json_encode($auth0_response));
        $access_token = (isset($auth0_response['access_token']))? $auth0_response['access_token'] : false;
        $id_token = (isset($auth0_response['id_token']))? $auth0_response['id_token'] : false;

        if (!$access_token) {
            throw new ApiException('Invalid access_token - Retry login.');
        }

        if (!$id_token) { // id_token is not mandatory anymore. There is no need to force openid connect
            $this->debugInfo('Missing id_token after code exchange. Remember to ask for openid scope.');
        }

        // Set the access token in the oauth client for future calls to the Auth0 API
        $this->oauth_client->setAccessToken($access_token);
        $this->oauth_client->setAccessTokenType(Client::ACCESS_TOKEN_BEARER);

        // Set it and persist it, if needed
        $this->setAccessToken($access_token);
        $this->setIdToken($id_token);

        return [$this->getAccessToken(), $this->getIdToken()];
    }
}
