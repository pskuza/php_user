<?php

use PHPUnit\Framework\TestCase;

class UserMysqlTest extends TestCase
{
    public function testUser()
    {
        //run php web server in tests dir
        shell_exec('cd tests && php -S 127.0.0.1:8080 >/dev/null 2>/dev/null &');
        //give php some time for the webserver
        sleep(5);
        $client = new GuzzleHttp\Client(['cookies' => true]);

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=0');

        $this->assertEquals('0', $r->getBody()->getContents(), 'Invalid email was taken for registration.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=1');

        $this->assertEquals('0', $r->getBody()->getContents(), 'Weak password was taken for registration.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=2');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not register with valid email and strong password.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=3');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not login with valid email and password.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=5');

        $old_password = $r->getBody()->getContents();

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=6');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not log out the user.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=4');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not login with changes hash options.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=5');

        $new_password = $r->getBody()->getContents();

        $this->assertNotEquals($old_password, $new_password, 'Rehash of password did not work.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=7');

        $this->assertNotEquals(0, $r->getBody()->getContents(), 'Check login did not work.');
    }
}
