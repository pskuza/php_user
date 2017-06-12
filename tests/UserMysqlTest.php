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

        $this->assertEquals('0', $r->getBody()->getContents(), 'Could login for a non confirmed account.');

        //confirm the account here .....
        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=10');

        $confirmation_token = $r->getBody()->getContents();

        $invalid_token = $confirmation_token;
        $invalid_token[0] = "g";

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=11&token='.$invalid_token);

        $this->assertEquals('0', $r->getBody()->getContents(), 'Could confirm account with invalid token.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=11&token='.$confirmation_token);

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not confirm account with valid token.');

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

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=8');

        $this->assertEquals('1', $r->getBody()->getContents(), 'changePassword did not work.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=7');

        $this->assertEquals(0, $r->getBody()->getContents(), 'changePassword did not logout the session.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=3');

        $this->assertEquals('0', $r->getBody()->getContents(), 'Could login with valid email and old invalid password after changePassword.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=9');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not login with valid email and password after changePassword.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=6');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not log out the user.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=13');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not request password reset.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=13');

        $this->assertEquals('0', $r->getBody()->getContents(), 'Could request password reset for already existing reset.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=12');

        $reset_token = $r->getBody()->getContents();

        $invalid_reset_token = $reset_token;
        $invalid_reset_token[0] = "g";

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=14&token='.$invalid_reset_token);

        $this->assertEquals('0', $r->getBody()->getContents(), 'Could reset account password with invalid token.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=14&token='.$reset_token);

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not reset account password with valid token.');

        $r = $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=15');

        $this->assertEquals('1', $r->getBody()->getContents(), 'Could not login after reset password.');

        $i = 0;
        while ($i < 10) {
            //make failed logins with valid email and wrong password
            $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=9');
            $i++;
        }

        $i = 0;
        while ($i < 10) {
            //make failed logins with valid email and wrong password
            $client->request('GET', 'http://127.0.0.1:8080/UserMysql.php?tests=16');
            $i++;
        }
    }
}
