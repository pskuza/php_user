<?php

//declare(strict_types=1);

namespace php_user;

class user
{
    protected $session = null;

    public function __construct(\php_session\session $session)
    {
        $this->session = $session;
    }

    public function login()
    {

    }

    public function checklogin()
    {

    }

    public function register(string $email, string $password)
    {

    }

    public function logout()
    {

    }
}
