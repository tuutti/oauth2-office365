<?php
/**
 * @file
 * Contains Tuutti\Oauth2\Client\Provider\Office365.
 */

namespace Tuutti\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Office365Provider Extends AbstractProvider {

  const BASE_URL = 'https://login.microsoftonline.com';
  const DEFAULT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
  public $defaultScopes = ['Calendar.ReadWrite'];

  protected $privateKey;
  protected $thumbPrint;
  protected $tenantId;
  protected $clientAssertion;
  protected $clientAssertionType;
  protected $resource;


  /**
   * {@inheritdoc}
   */
  public function __construct(array $options = [], array $collaborators = [])
  {
    foreach ($options as $option => $value) {
      if (property_exists($this, $option)) {
        $this->{$option} = $value;
      }
    }
    $options = array_merge($options, [
      'clientAssertion' => $this->requestSignature(),
      'clientAssertionType' => isset($options['clientAssertionType']) ? $options['clientAssertionType'] : self::DEFAULT_ASSERTION_TYPE,
    ]);

    parent::__construct($options, $collaborators);
  }

  /**
   * {@inheritdoc}
   */
  public function getBaseAccessTokenUrl(array $params = [])
  {
    return sprintf('%s/%s/oauth2/token', self::BASE_URL, $this->tenantId);
  }

  /**
   * {@inheritdoc}
   */
  public function getBaseAuthorizationUrl()
  {
    return sprintf('%s/%s/oauth2/authorize', self::BASE_URL, $this->tenantId);
  }

  /**
   * {@inheritdoc}
   */
  protected function getRequiredOptions()
  {
    return [
      'urlAuthorize',
      'urlAccessToken',
      'urlResourceOwnerDetails',
      'tenantId',
      'thumbPrint',
      'resource',
    ];
  }

  /**
   * {@inheritdoc}
   */
  protected function getRequiredRequestParameters()
  {
    return [
      'clientAssertion',
      'clientAssertionType',
      'resource',
    ];
  }

  /**
   * {@inheritdoc}
   */
  protected function createResourceOwner(array $response, AccessToken $token)
  {
    return null;
  }

  /**
   * {@inheritdoc}
   */
  protected function checkResponse(ResponseInterface $response, $data)
  {
    if (isset($data['error'])) {
      throw new IdentityProviderException($response->getReasonPhrase(), $response->getStatusCode(), $response);
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getResourceOwnerDetailsUrl(AccessToken $token)
  {
    return null;
  }

  /**
   * {@inheritdoc}
   */
  public function getDefaultScopes()
  {
    return $this->defaultScopes;
  }

  /**
   * Get request signature.
   */
  protected function requestSignature()
  {
    $time = time();
    $header = json_encode([
      'alg' => 'RS256',
      'x5t' => $this->thumbPrint,
    ]);
    $payload = json_encode([
      'aud' => $this->getBaseAccessTokenUrl(),
      'nbf' => $time,
      'exp' => $time + (60 * 15),
      'jti' => uniqid(),
      'sub' => $this->clientId,
      'iss' => $this->clientId,
    ]);

    $base64_token = sprintf('%s.%s', base64_encode($header), base64_encode($payload));
    $signature = $this->sign($base64_token);

    return sprintf('%s.%s', $base64_token, base64_encode($signature));
  }

  /**
   * Sign data with private key.
   */
  protected function sign($data)
  {
    $pkeyid = openssl_pkey_get_private($this->privateKey);

    openssl_sign($data, $signature, $pkeyid, OPENSSL_ALGO_SHA256);
    // Free key from memory.
    openssl_free_key($pkeyid);

    return $signature;
  }

  /**
   * {@inheritdoc}
   */
  public function getAccessToken($grant, array $options = [])
  {
    $grant = $this->verifyGrant($grant);
    $params = [
      'client_id'             => $this->clientId,
      'redirect_uri'          => $this->redirectUri,
      'client_assertion'      => $this->clientAssertion,
      'client_assertion_type' => $this->clientAssertionType,
      'resource'              => $this->resource,
    ];
    $params   = $grant->prepareRequestParameters($params, $options);
    $request  = $this->getAccessTokenRequest($params);
    $response = $this->getResponse($request);
    $prepared = $this->prepareAccessTokenResponse($response);

    return $this->createAccessToken($prepared, $grant);
  }

  /**
   * Overrides AbstractProvider::getAuthorizationHeaders().
   */
  protected function getAuthorizationHeaders($token = null)
  {
    if (!$token || !$token instanceof AccessToken) {
      throw new IdentityProviderException('Token not found.', null, null);
    }
    return ['Authorization' => 'Bearer ' . $token->getToken()];
  }
}
