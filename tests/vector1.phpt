--TEST--
Tests the first test vector described in RFC 2104
(http://www.ietf.org/rfc/rfc2104.txt)

--FILE--
<?php

require_once 'Crypt/HMAC.php';

$key  = str_repeat(chr(0x0b), 16);
$hmac = new Crypt_HMAC($key, 'md5');
echo $hmac->hash('Hi There')."\n";

?>

--EXPECT--
9294727a3638bb1c13f48ef8158bfc9d
