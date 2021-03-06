<?php

declare(strict_types=1);

namespace php_user;

class session extends \php_session\session
{
    //override the gc function from php_session to make it delete logins entries before deleting sessions
    public function gc($max) : bool
    {
        $rows = $this->db->run('SELECT id FROM sessions WHERE timestamp < ? AND remember_me = 0', time() - intval($max));
        $this->db->beginTransaction();
        foreach ($rows as $row) {
            //delete from cache and db
            $this->session_cache->delete($this->session_cache_identifier.$row['id']);
            $this->db->delete('logins', [
                'sessions_id' => $row['id'],
            ]);
            $this->db->delete('sessions', [
                'id' => $row['id'],
            ]);
        }
        $now = time() - 3600;
        //delete failed attempts older than 1 hour
        $this->db->run('DELETE FROM fail_ip WHERE timestamp > ?', $now);
        $this->db->run('DELETE FROM fail_users WHERE timestamp > ?', $now);
        $this->db->commit();

        return true;
    }
}
