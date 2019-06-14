<?php
/**  
* OpenID Connect Authentication with Oauthsd
* @link     https://oa.dnc.global
* Oauthsd.php OAuth service for the Lusitanian PHPoAuthLib 
* @link     https://github.com/Lusitanian/PHPoAuthLib
* @author   Bertrand Degoy bertrand@degoy.com
* @copyright (c) 2018 B.Degoy DnC https://degoy.com
* @license  http://www.opensource.org/licenses/mit-license.html MIT License
*/ 

//dnc4

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;


class Oauthsd extends AbstractService
{

    /**
    * Available scopes (will be tested by AbstractService). 
    * Might be larger than those defined by client application.
    * @link https://oa.dnc.global/-Sujets-communs-.html#definitionetgestiondesscopesdansOAuthsd
    * @see  #attributes
    */
    const SCOPE_OPENID           = 'openid';
    const SCOPE_PROFILE          = 'profile';
    const SCOPE_EMAIL            = 'email';
    const SCOPE_ADDRESS          = 'address';
    const SCOPE_PHONE            = 'phone';
    const SCOPE_SLI              = 'sli';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {

        $scopes = array_merge($scopes, array(openid, sli, profile));   // profile ???

        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://oa.dnc.global/');
        }
    }

    /**
    * Override abstract function in order to provide required parameters in authorization request.
    * State is required by OAuthSD
    * Scopes :
    * openid is required by OpenID Connect, sli is particular to OAuthSD, basic is enough for phpBB.
    * @link https://oa.dnc.global/-Sujets-communs-.html#definitionetgestiondesscopesdansOAuthsd
    */
    public function getAuthorizationUri(array $additionalParameters = array())
    {
        $parameters = array_merge(
            $additionalParameters,
            array(
                //'type'          => 'web_server',
                'client_id'     => $this->credentials->getConsumerId(),
                'redirect_uri'  => $this->credentials->getCallbackUrl(),
                'response_type' => 'code',
                'scope'         => 'openid sli',    // do not mention basic.       
            )
        );

        if (!isset($parameters['state'])) {
            $parameters['state'] = $this->generateAuthorizationState();
        }
        $this->storeAuthorizationState($parameters['state']);

        // Build the url
        $url = clone $this->getAuthorizationEndpoint();
        foreach ($parameters as $key => $val) {
            $url->addToQuery($key, $val);
        }
        return $url;
    }

    /**
    * {@inheritdoc}
    */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://oa.dnc.global/authorize');
    }

    /**
    * {@inheritdoc}
    */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://oa.dnc.global/token');
    }

    /**
    * {@inheritdoc}
    */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;        // ou AUTHORIZATION_METHOD_QUERY_STRING ???
    }

    /**
    * {@inheritdoc}
    */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['message'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['message'] . '"');
        } elseif (isset($data['name'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['name'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        $token->setLifeTime($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
    * {@inheritdoc}
    */
    public function requestAccessToken($code, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $bodyParams = array(
            'code'          => $code,
            'client_id'     => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'redirect_uri'  => $this->credentials->getCallbackUrl(),
            'grant_type'    => 'authorization_code',
        );

        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $bodyParams,
            $this->getExtraOAuthHeaders()
        );
        
        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }
}
