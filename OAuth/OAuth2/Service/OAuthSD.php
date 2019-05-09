<?php
//dnc3
  
namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;


/** OpenID Connect Authentication with OAuthSD
* @link https://oa.dnc.global
* @author Bertrand Degoy bertrand@degoy.com
* @copyright (c) 2018 B.Degoy DnC https://degoy.com
*/
class OAuthSD extends AbstractService
{
    /**
     * Defined scopes
     * @link https://oa.dnc.global/-Sujets-communs-.html#definitionetgestiondesscopesdansoauthsd
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
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://oa.dnc.global/');
        }
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
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
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
}

