<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Class to calculate RFC 2104 compliant hashes
 *
 * PHP versions 4 and 5
 *
 * LICENSE: This source file is subject to version 3.0 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_0.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @category   Encryption
 * @package    Crypt_HMAC
 * @author     Derick Rethans <derick@php.net>
 * @author     Matthew Fonda <mfonda@dotgeek.org>
 * @copyright  1997-2005 The PHP Group
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    CVS: $Id$
 * @link       http://pear.php.net/package/Crypt_HMAC
 * @link       http://www.ietf.org/rfc/rfc2104.txt
 */

/**
 * Calculates RFC 2104 compliant HMACs
 *
 * @category   Encryption
 * @package    Crypt_HMAC
 * @author     Derick Rethans <derick@php.net>
 * @author     Matthew Fonda <mfonda@dotgeek.org>
 * @copyright  1997-2005 The PHP Group
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @link       http://pear.php.net/package/Crypt_HMAC
 * @link       http://www.ietf.org/rfc/rfc2104.txt
 */
class Crypt_HMAC
{
    /**
     * Hash function to use
     *
     * @var string
     * @access private
     */
    var $_func;

    /**
     * Inner padded key
     *
     * @var string
     * @access private
     */
    var $_ipad;

    /**
     * Outer padded key
     *
     * @var string
     * @access private
     */
    var $_opad;

    /**
     * Pack format
     *
     * @var string
     * @access private
     */
    var $_pack;

    /**
     * Constructor
     *
     * @param string $key  the key to use for hashing.
     * @param string $func the hash function used for the calculation.
     *
     * @return void
     *
     * @access public
     */
    function Crypt_HMAC($key, $func = 'md5')
    {
        $this->setFunction($func);
        $this->setKey($key);
    }

    /**
     * Sets the hash function to use
     *
     * @param string $func the hash function to use.
     *
     * @return void
     *
     * @access public
     */
    function setFunction($func)
    {
        if (!$this->_pack = $this->_getPackFormat($func)) {
            die('Unsupported hash function');
        }
        $this->_func = $func;
    }

    /**
     * Sets key to use with hash
     *
     * Note: {@link Crypt_HMAC::setFunction()} must be called before setting
     * the key.
     *
     * @param string $key the key to use.
     *
     * @return void
     *
     * @access public
     */
    function setKey($key)
    {
        // Pad the key as the RFC wishes
        $func = $this->_func;

        if (strlen($key) > 64) {
           $key =  pack($this->_pack, $func($key));
        }
        if (strlen($key) < 64) {
            $key = str_pad($key, 64, chr(0));
        }

        // Calculate the padded keys and save them
        $this->_ipad = (substr($key, 0, 64) ^ str_repeat(chr(0x36), 64));
        $this->_opad = (substr($key, 0, 64) ^ str_repeat(chr(0x5c), 64));
    }

    /**
     * Gets pack formats for specifed hash function
     *
     * @param string $func the hash function for which to get the pack format.
     *
     * @return mixed the pack format or false if hash function does not exist.
     *
     * @access private
     */
    function _getPackFormat($func)
    {
        $packs = array(
            'md5'  => 'H32',
            'sha1' => 'H40'
        );

        return isset($packs[$func]) ? $packs[$func] : false;
    }

    /**
     * Gets the hash of a string
     *
     * @param  string  $data      the string that will be hashed.
     * @param  boolean $rawOutput if true the message digest is returned in raw
     *                            binary format.
     *
     * @return string the hashed string.
     *
     * @access public
     */
    function hash($data, $rawOutput = false)
    {
        switch ($this->_func) {
        case 'sha1':
            $hash = sha1($this->_ipad . $data);
            break;

        default:
        case 'md5':
            $hash = md5($this->_ipad . $data);
            break;
        }

        $hash = $this->_opad . pack($this->_pack, $hash);

        switch ($this->_func) {
        case 'sha1':
            $hash = sha1($hash);
            break;

        default:
        case 'md5':
            $hash = md5($hash);
            break;
        }

        if ($rawOutput) {
            $hash = pack('H*', $hash);
        }

        return $hash;
    }
}

?>
