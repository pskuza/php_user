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
        if(empty($email)) {
            //no email
            return false;
        }

        if(empty($password)) {
            //no password
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
    }

    public function logout()
    {
    }
}
