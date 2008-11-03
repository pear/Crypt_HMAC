--TEST--
Tests the second test vector described in RFC 2104
(http://www.ietf.org/rfc/rfc2104.txt)

--FILE--
<?php

require_once 'Crypt/HMAC.php';

$key  = 'Jefe';
$hmac = new Crypt_HMAC($key, 'md5');
echo $hmac->hash('what do ya want for nothing?')."\n";

?>

--EXPECT--
750c783e6ab0b503eaa86e310a5db738
