<?php

//declare(strict_types=1);

namespace php_user;

use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\RFCValidation;
use ZxcvbnPhp\Zxcvbn;
use AESGCM\AESGCM;

class user
{
    protected $session;

    protected $db;

    protected $minimum_password_strength_zxcvbn;

    protected $password_hash_options = ['cost' => 11];

    public function __construct(\php_session\session $session, \ParagonIE\EasyDB\EasyDB $db, int $minimum_password_strength_zxcvbn = 1)
    {
        $this->session = $session;

        $this->db = $db;

        $this->minimum_password_strength_zxcvbn = $minimum_password_strength_zxcvbn;

    }

    public function login()
    {
    }

    public function checklogin()
    {
    }

    public function register(string $email, string $password)
    {
        //to do: add messages to all falses

        if(empty($email)) {
            //no email
            return false;
        }

        if(empty($password) || !is_string($password)) {
            //no password, or not string
            return false;
        }

        $validator = new EmailValidator();
        if(!$validator->isValid($email, new RFCValidation())) {
            //not valid
            return false;
        }

        $zxcvbn = new Zxcvbn();
        $strength = $zxcvbn->passwordStrength($password, [$email]);
        if($strength['score'] <= $this->minimum_password_strength_zxcvbn) {
            //too weak
            return false;
        }

        //check if email is taken
        if($this->db->cell('SELECT id FROM users WHERE email = ?', $email)) {
            // already taken
            return false;
        }

        //everything looks fine, register user

        $hash = \password_hash(base64_encode(\hash('sha384', $password, true)),PASSWORD_DEFAULT, $this->password_hash_options);

        //generate key and iv
        $iv = bin2hex(random_bytes(12));
        $key = bin2hex(random_bytes(24));

        $ciphertext = $this->encrypt($hash, $key, $iv);


        return $this->db->insert('users', [
            'email'          => $email,
            'password'        => $ciphertext,
            'key'   => $key,
            'iv' => $iv,
        ]);
    }

    public function logout()
    {
    }

    public function encrypt(string $plaintext, string $key, string $iv)
    {
        $C = \AESGCM\AESGCM::encryptAndAppendTag(hex2bin($key), hex2bin($iv), $plaintext, null);

        //check if it did encrypt

        return bin2hex($C);
    }

    public function decrypt(string $ciphertext, string $key, string $iv)
    {
        $P = \AESGCM\AESGCM::decryptWithAppendedTag(hex2bin($key), hex2bin($iv), $ciphertext, null);

        //check if it did decrypt

        return bin2hex($P);
    }
}
