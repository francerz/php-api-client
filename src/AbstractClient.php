<?php

namespace Francerz\ApiClient;

use Francerz\Http\Utils\HttpFactoryManager;
use Francerz\Http\Utils\HttpHelper;
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
    private $httpHelper;

    private $apiEndpoint;

    private $ownerAccessTokenSessionKey = 'access-token';
    private $handlerOwnerAccessTokenLoad;
    private $handlerOwnerAccessTokenChanged;
    private $handlerOwnerAccessTokenRevoke;

    private $clientAccessTokenSessionKey = 'access-token-client';
    private $handlerClientAccessTokenLoad;
    private $handlerClientAccessTokenChanged;
    private $handlerClientAccessTokenRevoke;

    public function __construct(HttpFactoryManager $httpFactory, ClientInterface $httpClient)
    {
        if (!isset($_SESSION)) session_start();

        $this->httpFactory = $httpFactory;
        $this->httpHelper = new HttpHelper($httpFactory);
        $this->httpClient = $httpClient;

        $this->oauth2 = new AuthClient($httpFactory, $httpClient);

        $this->loadDefaultAccessTokenHandlers();
        $this->loadDefaultClientAccessTokenHandlers();

        $self = $this;
        $this->oauth2->setOwnerAccessTokenChangedHandler(function(AccessToken $accessToken) use ($self) {
            call_user_func($self->handlerOwnerAccessTokenChanged, $accessToken);
        });
        $this->oauth2->setClientAccessTokenChangedHandler(function(AccessToken $accessToken) use ($self) {
            call_user_func($self->handlerClientAccessTokenChanged, $accessToken);
        });
    }

    protected function loadDefaultAccessTokenHandlers()
    {
        $oatsk = $this->ownerAccessTokenSessionKey;
        $this->setOwnerAccessTokenLoadHandler(function() use ($oatsk) {
            if (isset($_SESSION[$oatsk]) && $_SESSION[$oatsk] instanceof AccessToken) {
                $this->setOwnerAccessToken($_SESSION[$oatsk]);
            }
        });
        $this->setOwnerAccessTokenChangedHandler(function(AccessToken $accessToken) use ($oatsk) {
            $_SESSION[$oatsk] = $accessToken;
        });
        $this->setOwnerAccessTokenRevokeHandler(function() use ($oatsk) {
            if (isset($_SESSION[$oatsk]) && $_SESSION[$oatsk] instanceof AccessToken) {
                unset($_SESSION[$oatsk]);
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

    #region OAuth2 Owner AccessToken
    /**
     * @deprecated v0.2.4
     *
     * @param AccessToken $accessToken
     * @return void
     */
    public function setAccessToken(AccessToken $accessToken)
    {
        $this->setOwnerAccessToken($accessToken);
    }

    /**
     * @deprecated v0.2.4
     *
     * @return void
     */
    public function getAccessToken()
    {
        return $this->getOwnerAccessToken();
    }

    public function setOwnerAccessToken(AccessToken $accessToken)
    {
        $this->oauth2->setOwnerAccessToken($accessToken);
    }

    public function getOwnerAccessToken()
    {
        return $this->oauth2->getOwnerAccessToken();
    }

    /**
     * @deprecated v0.2.4 Use setOwnerAccessTokenSessionKey instead
     *
     * @param string $key
     * @return void
     */
    public function setAccessTokenSessionKey(string $key)
    {
        $this->setOwnerAccessTokenSessionKey($key);
    }
    public function setOwnerAccessTokenSessionKey(string $key)
    {
        $this->ownerAccessTokenSessionKey = $key;
    }

    /**
     * @deprecated v0.2.4
     *
     * @return string
     */
    public function getAccessTokenSessionKey() : string
    {
        return $this->getOwnerAccessTokenSessionKey();
    }
    public function getOwnerAccessTokenSessionKey() : string
    {
        return $this->ownerAccessTokenSessionKey;
    }

    /**
     * @deprecated v0.2.4 Use setOwnerAccessTokenLoadHandler instead
     *
     * @param callable $handler
     * @return void
     */
    public function setAccessTokenLoadHandler(callable $handler)
    {
        $this->setOwnerAccessTokenLoadHandler($handler);
    }

    public function setOwnerAccessTokenLoadHandler(callable $handler)
    {
        $this->handlerOwnerAccessTokenLoad = $handler;
    }

    /**
     * @deprecated v0.2.4 Use setOwnerAccessTokenChangedHandler instead
     *
     * @param callable $handler
     * @return void
     */
    public function setAccessTokenChangedHandler(callable $handler)
    {
        $this->setOwnerAccessTokenChangedHandler($handler);
    }

    public function setOwnerAccessTokenChangedHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AccessToken::class])) {
            throw new InvalidArgumentException(__METHOD__.' callable signature must be: fn(AccessToken):void');
        }
        $this->handlerOwnerAccessTokenChanged = $handler;
    }

    /**
     * @deprecated v0.2.4 Use setOwnerAccessTokenRevokeHandler instead
     *
     * @param callable $handler
     * @return void
     */
    public function setAccessTokenRevokeHandler(callable $handler)
    {
        $this->setOwnerAccessTokenRevokeHandler($handler);
    }

    public function setOwnerAccessTokenRevokeHandler(callable $handler)
    {
        $this->handlerOwnerAccessTokenRevoke = $handler;
    }


    /**
     * @deprecated v0.2.4 Use loadOwnerAccessToken instead
     *
     * @return void
     */
    public function loadAccessToken()
    {
        $this->loadOwnerAccessToken();
    }
    public function loadOwnerAccessToken()
    {
        call_user_func($this->handlerOwnerAccessTokenLoad);
    }

    /**
     * @deprecated v0.2.4 Use revokeOwnerAccessToken instead
     *
     * @return void
     */
    public function revokeAcccessToken()
    {
        $this->revokeOwnerAcccessToken();
    }
    public function revokeOwnerAcccessToken()
    {
        call_user_func($this->handlerOwnerAccessTokenRevoke);
    }
    #endregion

    #region OAuth2 Client AccessToken
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
            $request = $this->httpHelper->getCurrentRequest();
        }
        return $this->oauth2->handleCallbackRequest($request);
    }

    public function getRedir(string $defaultUri)
    {
        $uriFactory = $this->httpFactory->getUriFactory();
        $currentUri = UriHelper::getCurrent($uriFactory);
        $redirUri = UriHelper::getQueryParam($currentUri, 'redir');
        if (UriHelper::isValid($redirUri)) {
            return $redirUri;
        }
        return $defaultUri;
    }
}