<?php

declare(strict_types=1);

namespace php_user;

use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\RFCValidation;
use ZxcvbnPhp\Zxcvbn;

class user
{
    protected $session;

    protected $db;

    protected $minimum_password_strength_zxcvbn;

    protected $encrypt_key;

    protected $password_hash_options = ['cost' => 11];

    protected $phpmailer;

    protected $twig;

    protected $email_header_subject = 'php_user';

    protected $confirm_email_url = 'https://example.com/confirm/';

    protected $reset_password_url = 'https://example.com/reset/';

    public function __construct(\php_session\session $session, \ParagonIE\EasyDB\EasyDB $db, int $minimum_password_strength_zxcvbn, string $encrypt_key, array $mail_settings, string $twig_template_dir)
    {
        $this->session = $session;

        $session->start();
        $session->generate_csrf();

        $this->db = $db;

        $this->minimum_password_strength_zxcvbn = $minimum_password_strength_zxcvbn;

        if (empty($encrypt_key) || strlen($encrypt_key) !== 48) {
            throw new Exception('Invalid encryption key.');
        }

        $this->encrypt_key = hex2bin($encrypt_key);

        $phpmailer = new \PHPMailer();
        $phpmailer->isSMTP();
        $phpmailer->Host = $mail_settings['host'];
        $phpmailer->SMTPAuth = true;
        $phpmailer->Username = $mail_settings['username'];
        $phpmailer->Password = $mail_settings['password'];
        $phpmailer->SMTPSecure = $mail_settings['secure'];
        $phpmailer->Port = $mail_settings['port'];
        $phpmailer->setFrom($mail_settings['username']);
        $this->phpmailer = $phpmailer;

        $loader = new \Twig_Loader_Filesystem($twig_template_dir);
        $twig = new \Twig_Environment($loader);

        $this->twig = $twig;
    }

    public function setPasswordhash(array $options)
    {
        if ($this->password_hash_options !== $options) {
            $this->password_hash_options = $options;
        }
    }

    public function login(string $email, string $password) : bool
    {
        if ($this->checklogin()) {
            //already logged in
            return false;
        }

        if (empty($email)) {
            //no email
            return false;
        }

        if (empty($password) || !is_string($password)) {
            //no password, or not string
            return false;
        }

        if ($ciphertext = $this->db->row('SELECT id, password, status FROM users WHERE email = ?', $email)) {
            //check if status === 1
            if ($ciphertext['status'] === 0) {
                //email not confirmed yet, show resend button
                return false;
            } elseif ($ciphertext['status'] !== 1) {
                //acc blocked, disabled or whatever
                return false;
            }

            //decrypt it
            $parts = explode('|', $ciphertext['password']);

            $hash_compare = $this->decrypt(base64_decode($parts[1]), base64_decode($parts[0]));

            if (\password_verify(base64_encode(\hash('sha384', $password, true)), $hash_compare)) {
                //regenerate session id
                $this->session->regenerate_id();

                //password was correct, check if we need to rehash the password (options changed)
                if (\password_needs_rehash($hash_compare, PASSWORD_DEFAULT, $this->password_hash_options)) {
                    $hash = \password_hash(base64_encode(\hash('sha384', $password, true)), PASSWORD_DEFAULT, $this->password_hash_options);

                    $iv = random_bytes(12);

                    $rehash_encrypted = $this->encrypt($hash, $iv);

                    $this->db->update('users', [
                        'password' => base64_encode($iv).'|'.$rehash_encrypted,
                    ], [
                        'email' => $email,
                    ]);
                }

                //this will throw an exception should the record already exist (so we check at the top of login, if that session is already logged in...)
                return $this->db->insert('logins', [
                    'sessions_id'          => session_id(),
                    'users_id'             => $ciphertext['id'],
                ]);
            } else {
                $this->addBruteforce($email);
            }
        } else {
            $this->addBruteforce();
        }

        return false;
    }

    public function checklogin() : int
    {
        if ($user_id = $this->db->cell('SELECT users_id FROM logins WHERE sessions_id = ?', session_id())) {
            // already logged in

            return $user_id;
        }

        return 0;
    }

    public function register(string $email, string $password) : bool
    {
        //to do: add messages to all falses

        if (empty($email)) {
            //no email
            return false;
        }

        if (empty($password) || !is_string($password)) {
            //no password, or not string
            return false;
        }

        $validator = new EmailValidator();
        if (!$validator->isValid($email, new RFCValidation())) {
            //not valid
            return false;
        }

        $zxcvbn = new Zxcvbn();
        $strength = $zxcvbn->passwordStrength($password, [$email]);
        if ($strength['score'] <= $this->minimum_password_strength_zxcvbn) {
            //too weak
            return false;
        }

        //check if email is taken
        if ($this->db->cell('SELECT id FROM users WHERE email = ?', $email)) {
            // already taken
            return false;
        }

        //everything looks fine, register user

        $hash = \password_hash(base64_encode(\hash('sha384', $password, true)), PASSWORD_DEFAULT, $this->password_hash_options);

        $iv = random_bytes(12);

        $ciphertext = $this->encrypt($hash, $iv);

        $user_id = $this->db->insertGet('users', [
            'email'           => $email,
            'password'        => base64_encode($iv).'|'.$ciphertext,
        ], 'id');

        $token = bin2hex(random_bytes(24));

        $this->sendEmail('email.twig', $email, $this->email_header_subject.' - Confirm your mail address.', [
            'pageTitle'          => $this->email_header_subject.' - Confirm your mail address.',
            'preview'            => $this->email_header_subject.' - Confirm your mail address.',
            'email'              => $email,
            'message'            => 'You registered a '.$this->email_header_subject.' account. Please click the button or link below to confirm this address and enable your account.',
            'button'             => true,
            'button_link'        => $this->confirm_email_url.$token.'/'.urlencode($email),
            'buttontext'         => 'Confirm',
            'message2'           => 'Should you have difficulties enabling your account contact support.',
            'small_help_message' => 'If the button does not work visit the following link: '.$this->confirm_email_url.$token.'/'.urlencode($email),
            'company'            => 'php_user',
        ]);

        return $this->db->insert('confirmation', [
            'users_id'           => $user_id,
            'token'              => $token,
            'timestamp'          => time(),
        ]);
    }

    public function getEmail() : string
    {
        if ($email = $this->db->cell('SELECT email FROM users WHERE user_id = (SELECT users_id FROM logins WHERE sessions_id = ?)', session_id())) {
            // already taken
            return $email;
        }

        return '';
    }

    public function changePassword(string $old_password, string $new_password, string $email, bool $notify_email = true) : bool
    {
        if (empty($old_password) || !is_string($old_password)) {
            //no password, or not string
            return false;
        }

        if (empty($new_password) || !is_string($new_password)) {
            //no password, or not string
            return false;
        }

        $zxcvbn = new Zxcvbn();
        $strength = $zxcvbn->passwordStrength($new_password, [$email, $old_password]);
        if ($strength['score'] <= $this->minimum_password_strength_zxcvbn) {
            //too weak
            return false;
        }

        if ($ciphertext = $this->db->row('SELECT id, password FROM users WHERE email = ?', $email)) {
            //decrypt it
            $parts = explode('|', $ciphertext['password']);

            $hash_compare = $this->decrypt(base64_decode($parts[1]), base64_decode($parts[0]));

            if (\password_verify(base64_encode(\hash('sha384', $old_password, true)), $hash_compare)) {
                //password was correct now write new password in
                $hash = \password_hash(base64_encode(\hash('sha384', $new_password, true)), PASSWORD_DEFAULT, $this->password_hash_options);

                $iv = random_bytes(12);

                $ciphertext_new = $this->encrypt($hash, $iv);

                $this->db->update('users', ['password' => base64_encode($iv).'|'.$ciphertext_new], ['email' => $email]);

                //delete all logins for this id

                //send email if true
                if ($notify_email) {
                    $this->sendEmail('email.twig', $email, $this->email_header_subject.' - Your Password was changed.', [
                            'pageTitle'          => $this->email_header_subject.' - Your Password was changed.',
                            'preview'            => $this->email_header_subject.' - Your Password was changed.',
                            'email'              => $email,
                            'message'            => 'Someone (hopefully you) changed your current password to your '.$this->email_header_subject.' account.',
                            'button'             => false,
                            'message2'           => 'Should you have difficulties accessing your account again contact support.',
                            'small_help_message' => '',
                            'company'            => 'php_user',
                    ]);
                }

                $this->db->delete('logins', [
                    'users_id' => $ciphertext['id'],
                ]);

                return $this->logout();
            } else {
                $this->addBruteforce($email);
            }
        } else {
            $this->addBruteforce();
        }

        return false;
    }

    public function logout() : bool
    {
        //log the user out
        $this->db->delete('logins', [
            'sessions_id' => session_id(),
        ]);

        return $this->session->logout();
    }

    public function encrypt(string $plaintext, string $iv) : string
    {
        $C = \AESGCM\AESGCM::encryptAndAppendTag($this->encrypt_key, $iv, $plaintext, null);

        //check if it did encrypt

        return base64_encode($C);
    }

    public function decrypt(string $ciphertext, string $iv) : string
    {
        $P = \AESGCM\AESGCM::decryptWithAppendedTag($this->encrypt_key, $iv, $ciphertext, null);

        //check if it did decrypt

        return $P;
    }

    public function sendEmail(string $file, string $email, string $subject, array $twig_text) : bool
    {
        $path_parts = pathinfo($file);

        $template = $this->twig->loadTemplate($file);
        $template_text = $this->twig->loadTemplate($path_parts['filename'].'_text.'.$path_parts['extension']);

        $this->phpmailer->addAddress($email);
        $this->phpmailer->isHTML(true);

        $this->phpmailer->Subject = $subject;
        $this->phpmailer->Body = $template->render($twig_text);
        //remove the help message from plain text
        unset($twig_text['small_help_message']);
        $this->phpmailer->AltBody = $template_text->render($twig_text);

        if ($this->phpmailer->send()) {
            return true;
        }

        return false;
    }

    public function confirmEmail(string $token, string $email) : bool
    {
        //get token from email
        if ($token_db = $this->db->row('SELECT users_id, token, timestamp FROM confirmation WHERE users_id = (SELECT id FROM users WHERE email = ?)', $email)) {
            //check if the timestamp did not run out
            if ($token_db['timestamp'] <= time() - 10800) {
                //delete
                $this->db->delete('confirmation', [
                    'users_id' => $token_db['users_id'],
                ]);

                return false;
            }

            if (hash_equals($token_db['token'], $token)) {
                //delete the confirmation and set user status to 1

                $this->db->update('users', [
                    'status' => 1,
                ], [
                    'email' => $email,
                ]);

                $this->db->delete('confirmation', [
                    'users_id' => $token_db['users_id'],
                ]);

                return true;
            } else {
                $this->addBruteforce($email);
            }
        } else {
            $this->addBruteforce();
        }

        //token not found
        return false;
    }

    public function requestResetPassword(string $email) : bool
    {
        //check if the user exists and is not disabled
        if ($user_id = $this->db->row('SELECT id, status FROM users WHERE email = ?', $email)) {
            //check if status === 1
            if ($user_id['status'] === 0) {
                return false;
            } elseif ($user_id['status'] !== 1) {
                return false;
            }
            //check if a password request is not already in progress
            if ($timestamp = $this->db->cell('SELECT timestamp FROM reset WHERE users_id = ?', $user_id['id'])) {
                if ($timestamp <= time() - 10800) {
                    //delete
                    $this->db->delete('reset', [
                        'users_id' => $user_id['id'],
                    ]);

                    //resend new since old one is invalid
                    $token = bin2hex(random_bytes(24));
                    $this->sendEmail('email.twig', $email, $this->email_header_subject.' - Password reset request.', [
                        'pageTitle'          => $this->email_header_subject.' - Password reset request.',
                        'preview'            => $this->email_header_subject.' - Password reset request.',
                        'email'              => $email,
                        'message'            => 'Someone (hopefully you) requested to reset your '.$this->email_header_subject.' account password. Please click the button or link below to reset your password. If you did not request it you can safely ignore this email',
                        'button'             => true,
                        'button_link'        => $this->reset_password_url.$token.'/'.urlencode($email),
                        'buttontext'         => 'Reset',
                        'message2'           => 'Should you have difficulties enabling your account contact support.',
                        'small_help_message' => 'If the button does not work visit the following link: '.$this->reset_password_url.$token.'/'.urlencode($email),
                        'company'            => 'php_user',
                    ]);

                    return $this->db->insert('reset', [
                        'users_id'  => $user_id['id'],
                        'token'     => $token,
                        'timestamp' => time(),
                    ]);
                }
                //pasword request is in progress, maybe resend?
            } else {
                $token = bin2hex(random_bytes(24));
                $this->sendEmail('email.twig', $email, $this->email_header_subject.' - Password reset request.', [
                    'pageTitle'          => $this->email_header_subject.' - Password reset request.',
                    'preview'            => $this->email_header_subject.' - Password reset request.',
                    'email'              => $email,
                    'message'            => 'Someone (hopefully you) requested to reset your '.$this->email_header_subject.' account password. Please click the button or link below to reset your password. If you did not request it you can safely ignore this email',
                    'button'             => true,
                    'button_link'        => $this->reset_password_url.$token.'/'.urlencode($email),
                    'buttontext'         => 'Reset',
                    'message2'           => 'Should you have difficulties enabling your account contact support.',
                    'small_help_message' => 'If the button does not work visit the following link: '.$this->reset_password_url.$token.'/'.urlencode($email),
                    'company'            => 'php_user',
                ]);

                return $this->db->insert('reset', [
                    'users_id'  => $user_id['id'],
                    'token'     => $token,
                    'timestamp' => time(),
                ]);
            }
        } else {
            $this->addBruteforce();
        }

        return false;
    }

    public function confirmResetPassword(string $token, string $email, string $new_password) : bool
    {
        $zxcvbn = new Zxcvbn();
        $strength = $zxcvbn->passwordStrength($new_password, [$email]);
        if ($strength['score'] <= $this->minimum_password_strength_zxcvbn) {
            //too weak
            return false;
        }

        //get token from email
        if ($token_db = $this->db->row('SELECT users_id, token, timestamp FROM reset WHERE users_id = (SELECT id FROM users WHERE email = ?)', $email)) {
            //check if the timestamp did not run out
            if ($token_db['timestamp'] <= time() - 10800) {
                //delete
                $this->db->delete('reset', [
                    'users_id' => $token_db['users_id'],
                ]);

                return false;
            }

            if (hash_equals($token_db['token'], $token)) {
                //delete the confirmation and set user status to 1

                $hash = \password_hash(base64_encode(\hash('sha384', $new_password, true)), PASSWORD_DEFAULT, $this->password_hash_options);

                $iv = random_bytes(12);

                $ciphertext_new = $this->encrypt($hash, $iv);

                $this->db->update('users', ['password' => base64_encode($iv).'|'.$ciphertext_new], ['email' => $email]);

                $this->db->delete('reset', [
                    'users_id' => $token_db['users_id'],
                ]);

                return true;
            } else {
                $this->addBruteforce($email);
            }
        } else {
            $this->addBruteforce();
        }

        //token not found
        return false;
    }

    public function checkBruteforce(string $email = null) : bool
    {
        //returns a true or false depending on if the ip (or user) did too many failed requests in the last hour and we should show a captcha
        if (!is_null($email)) {
            if ($fu_count = $this->db->cell('SELECT COUNT(id) FROM fail_users WHERE users_id = (SELECT id FROM users WHERE email = ?)', $email)) {
                if ($fu_count > 10) {
                    return true;
                }
            }
        }
        if ($fi_count = $this->db->cell('SELECT COUNT(id) FROM fail_ip WHERE ip = INET6_ATON(?)', $_SERVER['REMOTE_ADDR'])) {
            if ($fi_count > 20) {
                return true;
            }
        }

        return false;
    }

    public function addBruteforce(string $email = null)
    {
        //add a row for user (if set) and ip into db
        if (!is_null($email)) {
            if ($users_id = $this->db->cell('SELECT id FROM users WHERE email = ?', $email)) {
                $this->db->insert('fail_users', [
                    'users_id'  => $users_id,
                    'timestamp' => time(),
                ]);
            }
        }

        $this->db->run('INSERT INTO fail_ip (ip, timestamp) VALUES (?, UNIX_TIMESTAMP())', inet_pton($_SERVER['REMOTE_ADDR']));
    }
}
