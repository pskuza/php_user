# php_user

[![Build Status](https://travis-ci.org/pskuza/php_user.svg?branch=master)](https://travis-ci.org/pskuza/php_user)
[![StyleCI](https://styleci.io/repos/93275012/shield?branch=master)](https://styleci.io/repos/93275012)

* Uses php_session for session management. (https://github.com/pskuza/php_session) 
* Checks for weak passwords. (https://github.com/bjeavons/zxcvbn-php) 
* Encrypts the password_hash with AES-GCM. (https://github.com/Spomky-Labs/php-aes-gcm)
* Forces a captcha on too many register/login attempts. (https://github.com/google/recaptcha)
* Uses templates to send emails for confirmation & reset. (https://github.com/twigphp/Twig)
* Uses PHPMailer for sending the actual emails. (https://github.com/PHPMailer/PHPMailer)


## Install

``` sh
php composer.phar require "pskuza/php_user"
```

### Basic usage and what works
``` php
<?php

require('vendor/autoload.php');

use php_user\user;

//for memcached as cache
//check doctrine/cache on how to use the others
$memcached = new Memcached();
$memcached->addServer('127.0.0.1', 11211);
$cacheDriver = new \Doctrine\Common\Cache\MemcachedCache();
$cacheDriver->setMemcached($memcached);

//for mysql session storage
//check pdo for other connection handlers
$db = \ParagonIE\EasyDB\Factory::create(
    'mysql:host=127.0.0.1;dbname=notdev',
    'notroot',
    'averysecurerandompassword'
);

$session = new php_session\session($db, $cacheDriver);

session_set_save_handler($session, true);

$user = new php_user\user($session, $db);

```
