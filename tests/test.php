<?php
	/* This test file implements the three test vectors as described in
	 * RFC 2104 (http://rfc.net/rfc2104.html) */
	require_once 'Crypt/HMAC.php';

	$key = str_repeat(chr(0x0b), 16);
	$crypt1 = new Crypt_HMAC($key, 'md5');
	echo $crypt1->hash('Hi There')."\n";

	$key = 'Jefe';
	$crypt2 = new Crypt_HMAC($key, 'md5');
	echo $crypt2->hash('what do ya want for nothing?')."\n";

	$key = str_repeat(chr(0xaa), 16);
	$data = str_repeat(chr(0xdd), 50);
	$crypt3 = new Crypt_HMAC($key, 'md5');
	echo $crypt3->hash($data)."\n";
?>
