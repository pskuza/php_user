<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

require '../vendor/autoload.php';

$memcached = new Memcached();
$memcached->setOption(Memcached::OPT_COMPRESSION, false);
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

$email_settings = ['host' => 'smtp.mailtrap.io', 'username' => 'b35483ce4181bf', 'password' => '26a55050943989', 'port' => 465, 'secure' => 'tls'];

$user = new php_user\user($session, $db, 1, $key, $email_settings);

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
    case 8:
        echo (int) $user->changePassword('03ae108840e45cac45a31820b8f12b99', '31420b7f1239d', 'test@example.com');
        break;
    case 9:
        echo (int) $user->login('test@example.com', '31420b7f1239d');
        break;
    case 10:
        echo $db->cell('SELECT token FROM confirmation WHERE users_id = (SELECT id FROM users WHERE email = ?)', 'test@example.com');
        break;
    case 11:
        echo (int) $user->confirmEmail($_GET['token'], 'test@example.com');
        break;
    case 12:
        echo $db->cell('SELECT token FROM reset WHERE users_id = (SELECT id FROM users WHERE email = ?)', 'test@example.com');
        break;
    case 13:
        echo (int) $user->requestResetPassword('test@example.com');
        break;
    case 14:
        echo (int) $user->confirmResetPassword($_GET['token'], 'test@example.com', 'SomeNewSecurePassword');
        break;
    case 15:
        echo (int) $user->login('test@example.com', 'SomeNewSecurePassword');
        break;
    case 16:
        echo (int) $user->login('nosuchemail@example.com', '31420b7f1239d');
        break;
}
