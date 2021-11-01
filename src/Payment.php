<?php

namespace QT\SpdbBank;

use Exception;
use GuzzleHttp\Client;

class Payment
{
    const HTTP_TIMEOUT = 6.0;
    const GATEWAY      = 'https://api.spdb.com.cn/spdb/prd/api/acquiring/';

    private $config = [];
    private $params = [];
    private $secret;
    private $clientId;
    private $privateKey;
    private $publicKey;
    private $debug;

    private $requireConfigs = [
        'subMechNoAcctID' => '子商户公众账号ID不能为空',
        'spdbMrchNo'      => '特约商户号不能为空',
        'terminalNo'      => '终端号',
        'secret'          => '秘钥不能为空',
        'mrchlInfmAdr'    => 'notify_url不能为空',
        'privateKey'      => '私钥不能为空',
        'publicKey'       => '公钥不能为空',
        'clientId'        => 'ClientID不能为空',
    ];

    public function __construct(array $config, bool $debug = false)
    {
        foreach ($this->requireConfigs as $k => $v) {
            if (empty($config[$k])) {
                throw new Exception($v);
            }
        }

        $this->params['subMechNoAcctID'] = $config['subMechNoAcctID'];
        $this->params['spdbMrchNo']      = $config['spdbMrchNo'];
        $this->params['mrchlInfmAdr']    = $config['mrchlInfmAdr'];
        $this->params['terminalNo']      = $config['terminalNo'];

        $this->secret     = $config['secret'];
        $this->clientId   = $config['clientId'];
        $this->privateKey = $config['privateKey'];
        $this->publicKey  = $config['publicKey'];
        $this->debug      = $debug;
    }

    public function pay(array $data)
    {
        $path = 'appPay/initiation';
        $data = array_merge($data, $this->params);

        return $this->post($data, $path);
    }

    private function post(array $data, string $path)
    {
        $json     = json_encode($data);
        $Client   = new Client([
            'timeout' => self::HTTP_TIMEOUT,
        ]);

        $Response = $Client->request('POST', self::GATEWAY . $path, [
            'headers' => [
                'X-SPDB-Client-ID'  => $this->clientId,
                'X-SPDB-SIGNATURE'  => $this->sign($this->privateKey, $json),
                'X-SPDB-Encryption' => 'true',
                'Content-Type'      => 'application/json'
            ],
            'body'    => $this->encrypt($json, $this->secret),
        ]);

        $result = $Response->getBody()->getContents();
        if ($Response->getStatusCode() !== 200) {
            throw new Exception('请求失败');
        }

        return json_decode($this->decrypt($result, $this->secret), true);
    }

    /**
     * sha1WithRSA加签
     */
    public function sign($private_key, $data)
    {
        $key = openssl_get_privatekey($private_key);
        openssl_sign($data, $sign, $key, OPENSSL_ALGO_SHA1);
        openssl_free_key($key);
        $sign = base64_encode($sign);

        return $sign;
    }

    /**
     * sha1WithRSA验签
     */
    function verify($publicKey, $sign, $data)
    {
        $signTemp = base64_decode($sign);
        $key      = openssl_pkey_get_public($publicKey);
        $result   = openssl_verify($data, $signTemp, $key, OPENSSL_ALGO_SHA1);
        openssl_free_key($key);

        return $result === 1;
    }

    /**
     * AES加密
     */
    function encrypt($msg, $secret, $iv = null)
    {
        $secretTemp       = md5(hash("sha256", $secret, false));
        $ivSize           = openssl_cipher_iv_length('AES-128-CBC');
        $key              = substr($secretTemp, 0, $ivSize);
        $iv               = substr($secretTemp, $ivSize);
        $encryptedMessage = openssl_encrypt($msg, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);

        return base64_encode($encryptedMessage);
    }

    /**
     * AES解密
     */
    function decrypt($encryptData, $secret)
    {
        $encryptDataTemp = base64_decode($encryptData);
        $secretTemp      = md5(hash("sha256", $secret, false));
        $ivSize          = openssl_cipher_iv_length('AES-128-CBC');
        $key             = substr($secretTemp, 0, $ivSize);
        $iv              = substr($secretTemp, $ivSize);

        return openssl_decrypt($encryptDataTemp, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * 已废弃mcrypt_encrypt
     */
    function deleted_encrypt($data, $secret)
    {
        $secretTemp = md5(hash("sha256", $secret, false));
        $key        = substr($secretTemp, 0, 16);
        $iv         = substr($secretTemp, 16);
        //PKCS5PADDING
        $blockSize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $pad       = $blockSize - (strlen($data) % $blockSize);
        $data      = $data . str_repeat(chr($pad), $pad);
        $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);

        return base64_encode($encrypted);
    }

    /**
     * 已废弃mcrypt_decrypt
     */
    function deleted_decrypt($encryptData, $secret)
    {
        $encryptDataTemp = base64_decode($encryptData);
        $secretTemp      = md5(hash("sha256", $secret, false));
        $key             = substr($secretTemp, 0, 16);
        $iv              = substr($secretTemp, 16);
        $decrypted       = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $encryptDataTemp, MCRYPT_MODE_CBC, $iv);
        //UNPKCS5PADDING
        $pad = ord($decrypted{strlen($decrypted) - 1});
        if ($pad > strlen($decrypted)) {
            return $decrypted;
        }
        if (strspn($decrypted, chr($pad), strlen($decrypted) - $pad) != $pad) {
            return $decrypted;
        }
        $decrypted = substr($decrypted, 0, -1 * $pad);

        return $decrypted;
    }
}
