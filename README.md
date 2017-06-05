# php_user

[![Build Status](https://travis-ci.org/pskuza/php_user.svg?branch=master)](https://travis-ci.org/pskuza/php_user)
[![StyleCI](https://styleci.io/repos/93275012/shield?branch=master)](https://styleci.io/repos/93275012)

* Uses php_session for session management. (https://github.com/pskuza/php_session) 
* to do


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

$user = new php_user\user($session);

```
