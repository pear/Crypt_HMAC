--TEST--
Tests the third test vector described in RFC 2104
(http://www.ietf.org/rfc/rfc2104.txt)

--FILE--
<?php

require_once 'Crypt/HMAC.php';

$key  = str_repeat(chr(0xaa), 16);
$data = str_repeat(chr(0xdd), 50);
$hmac = new Crypt_HMAC($key, 'md5');
echo $hmac->hash($data)."\n";

?>

--EXPECT--
56be34521d144c88dbb8c733f0e8b3f6
