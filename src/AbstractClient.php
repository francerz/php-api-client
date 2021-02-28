<?php

namespace Francerz\ApiClient;

use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\Http\Utils\MessageHelper;
use Francerz\Http\Utils\UriHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\OAuth2\Client\AuthClient;
use Francerz\PowerData\Exceptions\InvalidOffsetException;
use Francerz\PowerData\Functions;
use InvalidArgumentException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

abstract class AbstractClient
{
    private $oauth2;
    private $httpFactory;
    private $httpClient;

    private $apiEndpoint;

    private $accessTokenSessionKey = 'access-token';
    private $handlerAccessTokenLoad;
    private $handlerAccessTokenChanged;
    private $handlerAccessTokenRevoke;

    private $clientAccessTokenSessionKey = 'access-token-client';
    private $handlerClientAccessTokenLoad;
    private $handlerClientAccessTokenChanged;
    private $handlerClientAccessTokenRevoke;

    public function __construct(HttpFactoryManager $httpFactory, ClientInterface $httpClient)
    {
        $this->httpFactory = $httpFactory;
        $this->httpClient = $httpClient;

        $this->oauth2 = new AuthClient($httpFactory, $httpClient);

        $this->loadDefaultAccessTokenHandlers();
        $this->loadDefaultClientAccessTokenHandlers();

        $self = $this;
        $this->oauth2->setAccessTokenChangedHandler(function(AccessToken $accessToken) use ($self) {
            call_user_func($self->handlerAccessTokenChanged, $accessToken);
        });
        $this->oauth2->setClientAccessTokenChangedHandler(function(AccessToken $accessToken) use ($self) {
            call_user_func($self->handlerClientAccessTokenChanged, $accessToken);
        });
    }

    protected function loadDefaultAccessTokenHandlers()
    {
        $atsk = $this->accessTokenSessionKey;
        $this->setAccessTokenLoadHandler(function() use ($atsk) {
            if (isset($_SESSION[$atsk]) && $_SESSION[$atsk] instanceof AccessToken) {
                $this->setAccessToken($_SESSION[$atsk]);
            }
        });
        $this->setAccessTokenChangedHandler(function(AccessToken $accessToken) use ($atsk) {
            $_SESSION[$atsk] = $accessToken;
        });
        $this->setAccessTokenRevokeHandler(function() use ($atsk) {
            if (isset($_SESSION[$atsk]) && $_SESSION[$atsk] instanceof AccessToken) {
                unset($_SESSION[$atsk]);
            }
        });
    }

    protected function loadDefaultClientAccessTokenHandlers()
    {
        $catsk = $this->clientAccessTokenSessionKey;
        $this->setClientAccessTokenLoadHandler(function() use ($catsk) {
            if (isset($_SESSION[$catsk]) && $_SESSION[$catsk] instanceof AccessToken) {
                $this->setClientAccessToken($_SESSION[$catsk]);
            }
        });
        $this->setClientAccessTokenChangedHandler(function(AccessToken $accessToken) use ($catsk) {
            $_SESSION[$catsk] = $accessToken;
        });
        $this->setClientAccessTokenRevokeHandler(function() use ($catsk) {
            if (isset($_SESSION[$catsk]) && $_SESSION[$catsk] instanceof AccessToken) {
                unset($_SESSION[$catsk]);
            }
        });
    }

    public function setHttpFactoryManager(HttpFactoryManager $httpFactory)
    {
        $this->httpFactory = $httpFactory;
    }

    public function getHttpFactoryManager()
    {
        return $this->httpFactory;
    }

    public function setHttpClient(ClientInterface $httpClient)
    {
        $this->httpClient = $httpClient;
    }

    public function getHttpClient()
    {
        return $this->httpClient;
    }

    protected function setApiEndpoint($uri)
    {
        if (is_string($uri)) {
            $uri = $this->httpFactory->getUriFactory()->createUri($uri);
        }
        if (!$uri instanceof UriInterface) {
            throw new InvalidArgumentException(__METHOD__.' $uri argument must be string or UriInterface object.');
        }
        $this->apiEndpoint = $uri;
    }

    public function getApiEndpoint()
    {
        return $this->apiEndpoint;
    }

    public function setCallbackEndpoint($uri)
    {
        if (is_string($uri)) {
            $uri = $this->httpFactory->getUriFactory()->createUri($uri);
        }
        if (!$uri instanceof UriInterface) {
            throw new InvalidOffsetException(__METHOD__.' $uri argument MUST be string or UriInterface');
        }
        $this->oauth2->setCallbackEndpoint($uri);
    }

    protected function getOAuth2Client()
    {
        return $this->oauth2;
    }

    public function setClientId(string $client_id)
    {
        $this->oauth2->setClientId($client_id);
    }

    public function setClientSecret(string $client_secret)
    {
        $this->oauth2->setClientSecret($client_secret);
    }

    #region OAuth2 AccessToken (resource owner)
    public function setAccessToken(AccessToken $accessToken)
    {
        $this->oauth2->setAccessToken($accessToken);
    }

    public function getAccessToken()
    {
        return $this->oauth2->getAccessToken();
    }

    public function setAccessTokenSessionKey(string $key)
    {
        $this->accessTokenSessionKey = $key;
    }

    public function getAccessTokenSessionKey() : string
    {
        return $this->accessTokenSessionKey;
    }

    public function setAccessTokenLoadHandler(callable $handler)
    {
        $this->handlerAccessTokenLoad = $handler;
    }

    public function setAccessTokenChangedHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AccessToken::class])) {
            throw new InvalidArgumentException(__METHOD__.' callable signature must be: func(AccessToken):void');
        }
        $this->handlerAccessTokenChanged = $handler;
    }

    public function setAccessTokenRevokeHandler(callable $handler)
    {
        $this->handlerAccessTokenRevoke = $handler;
    }

    public function loadAccessToken()
    {
        call_user_func($this->handlerAccessTokenLoad);
    }

    public function revokeAcccessToken()
    {
        call_user_func($this->handlerAccessTokenRevoke);
    }
    #endregion

    #region OAuth2 Client Access Token (client credentials)
    public function setClientAccessToken(AccessToken $accessToken)
    {
        $this->oauth2->setClientAccessToken($accessToken);
    }

    public function getClientAccessToken()
    {
        return $this->oauth2->getClientAccessToken();
    }

    public function setClientAccessTokenSessionKey(string $key)
    {
        $this->clientAccessTokenSessionKey = $key;
    }

    public function getClientAccessTokenSessionKey() : string
    {
        return $this->clientAccessTokenSessionKey;
    }

    public function setClientAccessTokenLoadHandler(callable $handler)
    {
        $this->handlerClientAccessTokenLoad = $handler;
    }

    public function setClientAccessTokenChangedHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AccessToken::class])) {
            throw new InvalidArgumentException(__METHOD__.' callable signature must be: func(AccessToken):void');
        }
        $this->handlerClientAccessTokenChanged = $handler;
    }

    public function setClientAccessTokenRevokeHandler(callable $handler)
    {
        $this->handlerClientAccessTokenRevoke = $handler;
    }

    public function loadClientAccessToken()
    {
        call_user_func($this->handlerClientAccessTokenLoad);
    }

    public function revokeClientAccessToken()
    {
        call_user_func($this->handlerClientAccessTokenRevoke);
    }
    #endregion

    protected function makeAuthorizeRedirUri($appAuthUri, string $redirKey = 'redir')
    {
        $uriFactory = $this->httpFactory->getUriFactory();
        
        if (is_string($appAuthUri)) {
            $appAuthUri = $uriFactory->createUri($appAuthUri);
        }
        
        if (!$appAuthUri instanceof UriInterface) {
            throw new InvalidArgumentException(__METHOD__.' $appAuthUri parameter MUST be string or UriInterface');
        }
        
        $currentUri = UriHelper::getCurrent($uriFactory);
        $appAuthUri = UriHelper::withQueryParam($appAuthUri, $redirKey, (string)$currentUri);
        
        return $appAuthUri;
    }

    protected function makeRequestAuthorizationCodeUri($callbackUri, array $scopes = [], string $state = '') : UriInterface
    {
        $this->oauth2->setCallbackEndpoint($callbackUri);
        $uri = $this->oauth2->getAuthorizationCodeRequestUri($scopes, $state);
        return $uri;
    }

    protected function handleAuthorizeResponse(?ServerRequestInterface $request = null)
    {
        if (is_null($request)) {
            MessageHelper::setHttpFactoryManager($this->httpFactory);
            $request = MessageHelper::getCurrentRequest();
        }
        return $this->oauth2->handleCallbackRequest($request);
    }

    public function getRedir(string $defaultUri)
    {
        $uriFactory = $this->httpFactory->getUriFactory();
        $currentUri = UriHelper::getCurrent($uriFactory);
        $redirUri = UriHelper::getQueryParam($currentUri, 'redir');
        if (isset($redirUri)) {
            return $redirUri;
        }
        return $defaultUri;
    }
}