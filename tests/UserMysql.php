<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

require '../vendor/autoload.php';

$memcached = new Memcached();
$memcached->addServer('127.0.0.1', 11211);

$cacheDriver = new \Doctrine\Common\Cache\MemcachedCache();
$cacheDriver->setMemcached($memcached);

$db = \ParagonIE\EasyDB\Factory::create(
    'mysql:host=localhost;dbname=dev',
    'root',
    ''
);

$session = new php_session\session($db, $cacheDriver, 0, false, true);

session_set_save_handler($session, true);

$user = new php_user\user($session, $db);

$key = "d3c8846372b98298187a9a127e04551894d66e777250445e";


switch ($_GET['tests']) {
    case 0:
        echo (int) $user->register('invalid.email@', "03ae108840e45cac45a31820b8f12b99", 1, $key);
        break;
    case 1:
        echo (int) $user->register('test@example.com', "abc", 1, $key);
        break;
    case 2:
        echo (int) $user->register('test@example.com', "03ae108840e45cac45a31820b8f12b99", 1, $key);
        break;
}