# Usage

```php
$provider = new \Tuutti\OAuth2\Client\Provider\Office365([
  'clientId' => 'some value',
  'redirectUri' => 'http://localhost....',
  'tenantId' => 'your tenant id',
  'thumbPrint' => ' your thumb print',
  'privateKey' => 'file://path_to_privatekey.pem',
  'resource' => 'your resource, usually https://outlook.office365.com/',
]);
$token = $provider->getAccessToken('client_credentials');
....
```
