<?php

//declare(strict_types=1);

namespace php_user;

use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\RFCValidation;
use ZxcvbnPhp\Zxcvbn;

class user
{
    protected $session;

    protected $db;

    protected $minimum_password_strength_zxcvbn;

    protected $encrypt_key;

    protected $password_hash_options = ['cost' => 11];

    public function __construct(\php_session\session $session, \ParagonIE\EasyDB\EasyDB $db, int $minimum_password_strength_zxcvbn, string $encrypt_key)
    {
        $this->session = $session;

        $session->start();
        $session->generate_csrf();

        $this->db = $db;

        $this->minimum_password_strength_zxcvbn = $minimum_password_strength_zxcvbn;

        if (empty($encrypt_key) || strlen($encrypt_key) !== 48) {
            throw new Exception('Invalid encryption key.');
            die();
        }

        $this->encrypt_key = hex2bin($encrypt_key);
    }

    public function setPasswordhash(array $options)
    {
        if ($this->password_hash_options !== $options) {
            $this->password_hash_options = $options;
        }
    }

    public function login(string $email, string $password)
    {
        if ($this->checklogin()) {
            //already logged in
            return false;
        }

        if (empty($email)) {
            //no email
            return false;
        }

        if (empty($password) || !is_string($password)) {
            //no password, or not string
            return false;
        }

        if ($ciphertext = $this->db->row('SELECT id, password FROM users WHERE email = ?', $email)) {
            //decrypt it
            $parts = explode('|', $ciphertext['password']);

            $hash_compare = $this->decrypt(base64_decode($parts[1]), base64_decode($parts[0]));

            if (\password_verify(base64_encode(\hash('sha384', $password, true)), $hash_compare)) {
                //regenerate session id
                $this->session->regenerate_id();

                //password was correct, check if we need to rehash the password (options changed)
                if (\password_needs_rehash($hash_compare, PASSWORD_DEFAULT, $this->password_hash_options)) {
                    $hash = \password_hash(base64_encode(\hash('sha384', $password, true)), PASSWORD_DEFAULT, $this->password_hash_options);

                    $iv = random_bytes(12);

                    $rehash_encrypted = $this->encrypt($hash, $iv);

                    $this->db->update('users', [
                        'password' => base64_encode($iv).'|'.$rehash_encrypted,
                    ], [
                        'email' => $email,
                    ]);
                }

                //this will throw an exception should the record already exist (so we check at the top of login, if that session is already logged in...)
                return $this->db->insert('logins', [
                    'sessions_id'          => session_id(),
                    'users_id'             => $ciphertext['id'],
                ]);
            }
        }

        return false;
    }

    public function checklogin()
    {
        if ($user_id = $this->db->cell('SELECT users_id FROM logins WHERE sessions_id = ?', session_id())) {
            // already logged in

            return $user_id;
        }

        return false;
    }

    public function register(string $email, string $password)
    {
        //to do: add messages to all falses

        if (empty($email)) {
            //no email
            return false;
        }

        if (empty($password) || !is_string($password)) {
            //no password, or not string
            return false;
        }

        $validator = new EmailValidator();
        if (!$validator->isValid($email, new RFCValidation())) {
            //not valid
            return false;
        }

        $zxcvbn = new Zxcvbn();
        $strength = $zxcvbn->passwordStrength($password, [$email]);
        if ($strength['score'] <= $this->minimum_password_strength_zxcvbn) {
            //too weak
            return false;
        }

        //check if email is taken
        if ($this->db->cell('SELECT id FROM users WHERE email = ?', $email)) {
            // already taken
            return false;
        }

        //everything looks fine, register user

        $hash = \password_hash(base64_encode(\hash('sha384', $password, true)), PASSWORD_DEFAULT, $this->password_hash_options);

        $iv = random_bytes(12);

        $ciphertext = $this->encrypt($hash, $iv);

        return $this->db->insert('users', [
            'email'           => $email,
            'password'        => base64_encode($iv).'|'.$ciphertext,
        ]);
    }

    public function getEmail()
    {
        if ($email = $this->db->cell('SELECT email FROM users WHERE user_id = (SELECT users_id FROM logins WHERE sessions_id = ?)', session_id())) {
            // already taken
            return $email;
        }
        return false;
    }

    public function changePassword(string $old_password, string $new_password, string $email)
    {
        if (empty($old_password) || !is_string($old_password)) {
            //no password, or not string
            return false;
        }

        if (empty($new_password) || !is_string($new_password)) {
            //no password, or not string
            return false;
        }

        $zxcvbn = new Zxcvbn();
        $strength = $zxcvbn->passwordStrength($new_password, [$email, $old_password]);
        if ($strength['score'] <= $this->minimum_password_strength_zxcvbn) {
            //too weak
            return false;
        }

        if ($ciphertext = $this->db->row('SELECT id, password FROM users WHERE email = ?', $email)) {
            //decrypt it
            $parts = explode('|', $ciphertext['password']);

            $hash_compare = $this->decrypt(base64_decode($parts[1]), base64_decode($parts[0]));

            if (\password_verify(base64_encode(\hash('sha384', $old_password, true)), $hash_compare)) {
                //password was correct now write new password in
                $hash = \password_hash(base64_encode(\hash('sha384', $new_password, true)), PASSWORD_DEFAULT, $this->password_hash_options);

                $iv = random_bytes(12);

                $ciphertext_new = $this->encrypt($hash, $iv);

                $this->db->update('users', ['password' => base64_encode($iv).'|'.$ciphertext_new,], ['email' => $email]);

                //delete all logins for this id

                $this->db->delete('logins', [
                    'users_id' => $ciphertext['id'],
                ]);

                return $this->logout();
            }
        }

        return false;
    }

    public function logout()
    {
        //log the user out
        $this->db->delete('logins', [
            'sessions_id' => session_id(),
        ]);

        return $this->session->logout();
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

        return $P;
    }
}
