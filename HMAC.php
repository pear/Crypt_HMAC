<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | PHP Version 4                                                        |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2003 The PHP Group                                |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.0 of the PHP license,       |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Authors: Derick Rethans <d.rethans@jdimedia.nl>                      |
// +----------------------------------------------------------------------+
//
// $Id$


/**
* Calculates RFC 2104 compliant HMACs
*
* @version $Revision$
* @access public
* @package Crypt
* @author Derick Rethans <d.rethans@jdimedia.nl>
 */   
class Crypt_HMAC {

    /**
    * Hash function to use
    * @var string
    */
    var $_func;

    /**
    * Inner padded key
    * @var string
    */
    var $_ipad;

    /**
    * Outer padded key
    * @var string
    */
    var $_opad;
    
    /**
    * Constructor
    * Pass method as first parameter
    *
    * @param  string method - Hash function used for the calculation
    * @return void
    * @access public
    */
    function Crypt_HMAC($key, $method = 'md5')
    {
        if (!in_array($method, array('sha1', 'md5'))) {
            die("Unsupported hash function '$method'.");
        }
        $this->_func = $method;

        /* Pad the key as the RFC wishes */
        if (strlen($key) > 64) {
            $key = pack('H32', $method($key));
        }

        if (strlen($key) < 64) {
            $key = str_pad($key, 64, chr(0));
        }

        /* Calculate the padded keys and save them */
        $this->_ipad = (substr($key, 0, 64) ^ str_repeat(chr(0x36), 64));
        $this->_opad = (substr($key, 0, 64) ^ str_repeat(chr(0x5C), 64));
    }
    
    /**
    * Hashing function
    *
    * @param  string data - string that will encrypted
    * @return string
    * @access public
    */
    function hash($data)
    {
        $func = $this->_func;
        $inner  = pack('H32', $func($this->_ipad . $data));
        $digest = $func($this->_opad . $inner);

        return $digest;
    }
}
?>
