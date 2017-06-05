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
    }
}
