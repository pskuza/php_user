<?php

//declare(strict_types=1);

namespace php_user;

use php_session\session;

class user
{
    protected $session = null;

    public function __construct(php_session\session $session)
    {
        $this->session = $session;
    }
}
