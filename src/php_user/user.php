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

    protected $encrypt_key;

    protected $password_hash_options = ['cost' => 11];

    public function __construct(\php_session\session $session, \ParagonIE\EasyDB\EasyDB $db, int $minimum_password_strength_zxcvbn = 1, string $encrypt_key)
    {
        $this->session = $session;

        $session->start();
        $session->generate_csrf();

        $this->db = $db;

        $this->minimum_password_strength_zxcvbn = $minimum_password_strength_zxcvbn;

        if(empty($encrypt_key) || strlen($encrypt_key) !== 48) {
            throw new Exception('Invalid encryption key.');
            die();
        }

        $this->encrypt_key = hex2bin($encrypt_key);

    }

    public function login(string $email, string $password)
    {
        //quick and simple hack so I know register works

        if(empty($email)) {
            //no email
            return false;
        }

        if(empty($password) || !is_string($password)) {
            //no password, or not string
            return false;
        }


        $hash = \password_hash(base64_encode(\hash('sha384', $password, true)),PASSWORD_DEFAULT, $this->password_hash_options);

        if($ciphertext = $this->db->cell('SELECT password FROM users WHERE email = ?', $email)) {
            //decrypt it
            //$parts = explode("|", $ciphertext);

            ///$hash_compare = $this->decrypt(base64_decode($parts[1]), base64_decode($parts[0]));

            return hash_equals($ciphertext, $hash);
        }

        return false;

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

        //$iv = random_bytes(12);

        //$ciphertext = $this->encrypt($hash, $iv);

        return $this->db->insert('users', [
            'email'          => $email,
            'password'        => $hash,
        ]);
    }

    public function logout()
    {
    }

    public function encrypt(string $plaintext, string $iv)
    {
        $C = \AESGCM\AESGCM::encryptAndAppendTag($this->encrypt_key, $iv, $plaintext, null);

        //check if it did encrypt

        return base64_encode($C);
    }

    public function decrypt(string $ciphertext, string $iv)
    {
        $P = \AESGCM\AESGCM::decryptWithAppendedTag($this->encrypt_key, $iv, $ciphertext, null);

        //check if it did decrypt

        return base64_encode($P);
    }
}
