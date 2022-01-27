<?php

namespace QT\SpdbBank;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Promise;

class Payment
{
    const HTTP_TIMEOUT = 6.0;
    const GATEWAY      = 'https://api.spdb.com.cn/spdb/prd/api/';

    private $config = [];
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

        $this->debug  = $debug;
        $this->config = $config;
    }

    public function pay(array $data)
    {
        $path = 'acquiring/appPay/initiation';
        $data = array_merge($data, [
            'subMechNoAcctID' => $this->config['subMechNoAcctID'],
            'spdbMrchNo'      => $this->config['spdbMrchNo'],
            'mrchlInfmAdr'    => $this->config['mrchlInfmAdr'],
            'terminalNo'      => $this->config['terminalNo'],
        ]);

        return $this->post($data, $path);
    }

    /**
     * APP支付交易查证
     * @param array  $data
     * @param $orderField $key 浦发交易流水号和商户订单号二者必选其一
     * @return array
     * @throws \Throwable
     */
    public function getPayStatus(array $data, $orderField = 'mrchOrdrNo')
    {
        $path     = 'electronic/appPayChk';
        $client   = new Client(['base_uri' => self::GATEWAY]);
        $promises = [];
        foreach ($data as $k => $v) {
            $json = json_encode([
                'subMechNoAcctID' => $this->config['subMechNoAcctID'],
                $orderField       => $v[$orderField] ?? '',
                'tranDate'        => $v['tranDate'],
                'spdbMrchNo'      => $this->config['spdbMrchNo'],
            ]);

            $promises[$k] = $client->postAsync($path, [
                'headers' => [
                    'X-SPDB-Client-ID'  => $this->config['clientId'],
                    'X-SPDB-SIGNATURE'  => $this->sign($json),
                    'X-SPDB-Encryption' => 'true',
                    'Content-Type'      => 'application/json'
                ],
                'body'    => $this->encrypt($json),
            ]);
        }

        $responses = Promise\Utils::unwrap($promises);
        $result    = [];
        foreach ($data as $k => $v) {
            $result[$k] = json_decode($this->decrypt($responses[$k]->getBody()->getContents()), true);
        }

        return $result;
    }

    /**
     * @param $amountm, 退款金额
     * @param $mrchOrdrNo, 商户订单号
     * @param $mrchOrigOrdrNo, 原收单系统订单号
     */
    public function refund(string $amountm, string $mrchOrdrNo, string $mrchOrigOrdrNo)
    {
        // 手续费最低收费为1分钱
        if ($amountm < 0.02) {
            throw new Exception('退款金额不能少于1分钱');
        }

        $path = 'acquiring/appPay/return';
        $data = [
            'subMechNoAcctID' => $this->config['subMechNoAcctID'],
            'tranAmt'         => $amountm,
            'mrchOrigOrdrNo'  => $mrchOrigOrdrNo,
            'mrchOrdrNo'      => $mrchOrdrNo,
            'mrchTm'          => date('YmdHis'),
            'terminalNo'      => $this->config['terminalNo'],
            'spdbMrchNo'      => $this->config['spdbMrchNo'],
        ];

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
                'X-SPDB-Client-ID'  => $this->config['clientId'],
                'X-SPDB-SIGNATURE'  => $this->sign($json),
                'X-SPDB-Encryption' => 'true',
                'Content-Type'      => 'application/json'
            ],
            'body'    => $this->encrypt($json),
            'debug'   => $this->debug
        ]);

        $result = $Response->getBody()->getContents();
        if ($Response->getStatusCode() !== 200) {
            throw new Exception('请求失败');
        }

        return json_decode($this->decrypt($result), true);
    }

    /**
     * sha1WithRSA加签
     */
    public function sign($data)
    {
        $key = openssl_get_privatekey($this->config['privateKey']);
        openssl_sign($data, $sign, $key, OPENSSL_ALGO_SHA1);
        $sign = base64_encode($sign);

        return $sign;
    }

    /**
     * sha1WithRSA验签
     */
    public function verify($sign, $data)
    {
        $signTemp = base64_decode($sign);
        $key      = openssl_pkey_get_public($this->config['publicKey']);
        $result   = openssl_verify($data, $signTemp, $key, OPENSSL_ALGO_SHA1);

        return $result === 1;
    }

    /**
     * AES加密
     */
    public function encrypt($msg, $iv = null)
    {
        $secretTemp       = md5(hash("sha256", $this->config['secret'], false));
        $ivSize           = openssl_cipher_iv_length('AES-128-CBC');
        $key              = substr($secretTemp, 0, $ivSize);
        $iv               = substr($secretTemp, $ivSize);
        $encryptedMessage = openssl_encrypt($msg, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);

        return base64_encode($encryptedMessage);
    }

    /**
     * AES解密
     */
    public function decrypt($encryptstr)
    {
        $data   = base64_decode($encryptstr);
        $secret = md5(hash("sha256", $this->config['secret'], false));
        $ivSize = openssl_cipher_iv_length('AES-128-CBC');
        $key    = substr($secret, 0, $ivSize);
        $iv     = substr($secret, $ivSize);

        return openssl_decrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * 使用合作方私钥解密
     */
    public function rsaDecrypt($encryptstr)
    {
        $keyClosure = openssl_pkey_get_private($this->config['privateKey']);
        $data       = base64_decode($encryptstr);
        $data       = str_split($data, $this->getDecryptBlockLen($keyClosure));
        $decrypt    = '';
        foreach ($data as $chunk)
        {
            openssl_private_decrypt($chunk, $encrypted, $keyClosure);
            $decrypt .= $encrypted;
        }

        return json_decode($decrypt, true);
    }

    protected function getDecryptBlockLen($keyClosure)
    {
        $keyInfo = openssl_pkey_get_details($keyClosure);
        if (!$keyInfo) {
            throw new Exception('获取密钥信息失败' . openssl_error_string());
        }

        return $keyInfo['bits'] / 8;
    }
}
