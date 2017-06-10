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

$key = 'd3c8846372b98298187a9a127e04551894d66e777250445e';

$user = new php_user\user($session, $db, 1, $key);

switch ($_GET['tests']) {
    case 0:
        echo (int) $user->register('invalid.email@', '03ae108840e45cac45a31820b8f12b99');
        break;
    case 1:
        echo (int) $user->register('test@example.com', 'abc');
        break;
    case 2:
        echo (int) $user->register('test@example.com', '03ae108840e45cac45a31820b8f12b99');
        break;
    case 3:
        echo (int) $user->login('test@example.com', '03ae108840e45cac45a31820b8f12b99');
        break;
    case 4:
        $user->setPasswordhash(['cost' => 12]);
        echo (int) $user->login('test@example.com', '03ae108840e45cac45a31820b8f12b99');
        break;
    case 5:
        echo $db->cell('SELECT password FROM users WHERE email = ?', 'test@example.com');
        break;
    case 6:
        echo (int) $user->logout();
        break;
    case 7:
        echo (int) $user->checklogin();
        break;
}
