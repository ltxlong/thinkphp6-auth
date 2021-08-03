<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK IT ]
// +----------------------------------------------------------------------
// | Copyright (c) ltxlong
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: 416803647@qq.com
// +----------------------------------------------------------------------
namespace think\auth;

use think\facade\Db;
use think\facade\Config;
use think\facade\Session;

/**
 * 权限认证类
 * 功能特性说明：
 * 1，是对规则进行认证，不是对节点进行认证。用户可以把节点当作规则名称实现对节点进行认证
 *      $auth = new Auth();  $flag = $auth->check('规则名称','用户id');
 *
 * 2，认证的场景
 *      可以对节点进行认证，也就是把节点作为规则
 *            这个节点就是 模块/控制器/方法
 *            把节点作为规则，那么这个规则名称就是'模块/控制器/方法'，也可以是'模块_控制器_方法'，也可以是'控制器_方法'等等
 *            通常节点作为规则认证，是在baseController（自定义的base，非框架自带的，继承框架自带的）里面进行认证的
 *      除了节点作为规则进行认证，就是自定义规则了
 *            自定义规则名称，如button_click
 *            自定义规则认证，在哪里都行，在任何的方法里
 *
 * 3，规则参数，可以是字符串，也可以是数组。推荐数组，因为最终都会转化为数组的。如果传入的$name是字符串，则会先全部转小写，再根据逗号分割为数组
 *      $auth = new Auth();  $flag = $auth->check(['规则1'], '用户id');
 *
 * 4，可以同时对多条规则进行认证，并设置多条规则的关系（or或者and）
 *      $auth = new Auth();  $flag = $auth->check(['规则1', '规则2'],'用户id','and');
 *      第三个参数为and时，表示用户需要同时具有规则1和规则2的权限。
 *      第三个参数为or时，表示用户只需要具有其中一个条件即可。
 *      第三个参数默认为or
 *
 * 5，一个用户可以属于多个用户组(auth_group_access表 定义了用户所属用户组)。我们需要设置每个用户组拥有哪些规则(auth_group 定义了用户组权限)
 *
 * 6，支持规则表达式
 *      在auth_rule的condition字段就可以定义规则表达式。
 *      如定义score>5 && score<100  表示用户的分数在5-100之间时这条规则才会通过。
 *      再复杂点的：score<50 && score<100 || name!=abc（注意，这里的abc不能用单引号或者双引号包裹）。
 *      注意：condition里的变量是用户表（配置auth_user的值的表，通常配置为用户表）的字段
 *      （当然，不配置auth_user的值为用户表，而是其他表，那也行的！但是，condition里的变量只能是配置的表里面的字段）
 *      （如配置auth_user的值为integral积分表，那么condition里的变量就只能是integral表里面的字段）
 *      支持的运算符号：>= > <= < && == || !=
 *      注意：不支持括号
 */
//数据库
/*
auth_type 实时认证和登录认证的区别：
实时认证就是每次认证都查表，而登录认证是查session
----------------------------------------------------------------------------
-- auth_rule，规则表，
-- id:主键，
-- name：规则唯一标识, title：规则中文名称 status 状态：为1正常，为0禁用
-- name 可以自定义名称，也可以是模块/控制器/方法、模块_控制器_方法、控制器_方法
-- condition：规则表达式，为空表示存在就验证，不为空表示按照条件验证
-- condition 简单来说，如果字段为空，则只验证name就行；如果字段不为空，则在验证了name的基础上，还要验证字段里面的条件
-- condition 条件，是user表的字段条件（准确来说，是auth_user配置的表），如 score > 10
----------------------------------------------------------------------------
DROP TABLE IF EXISTS `auth_rule`;
CREATE TABLE `auth_rule` (
    `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
    `name` varchar(80) NOT NULL DEFAULT '',
    `title` varchar(20) NOT NULL DEFAULT '',
    `status` tinyint(1) NOT NULL DEFAULT 1,
    `condition` varchar(100) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
----------------------------------------------------------------------------
-- auth_group 用户组表，
-- id：主键， title:用户组中文名称， rules：用户组拥有的规则id， 多个规则","隔开，status 状态：为1正常，为0禁用
----------------------------------------------------------------------------
DROP TABLE IF EXISTS `auth_group`;
CREATE TABLE `auth_group` (
    `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
    `title` varchar(100) NOT NULL DEFAULT '',
    `status` tinyint(1) NOT NULL DEFAULT 1,
    `rules` varchar(80) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
----------------------------------------------------------------------------
-- auth_group_access 用户-用户组关系表
-- uid:用户id，group_id：用户组id
----------------------------------------------------------------------------
DROP TABLE IF EXISTS `auth_group_access`;
CREATE TABLE `auth_group_access` (
    `uid` mediumint(8) unsigned NOT NULL,
    `group_id` mediumint(8) unsigned NOT NULL,
    UNIQUE KEY `uid_group_id` (`uid`,`group_id`),
    KEY `uid` (`uid`),
    KEY `group_id` (`group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
*/

class Auth
{
    /**
     * @var 对象实例
     */
    protected static $instance;

    /**
     * @var array 默认配置
     */
    protected $config = [
        'auth_on' => 1, // 权限开关
        'auth_type' => 1, // 认证方式，1为实时认证；2为登录认证。实时认证就是每次都查表，而登录认证是查session。
        'auth_group' => 'auth_group', // 用户组数据表
        'auth_group_access' => 'auth_group_access', // 用户-用户组关系表
        'auth_rule' => 'auth_rule', // 权限规则表
        'auth_user' => 'user', // 用户信息表
    ];

    /**
     * 构造函数
     */
    public function __construct()
    {
        // 可以设置配置项 auth
        // 如果没有配置，那就用默认的配置
        if ($auth = Config::get('auth')) {
            $this->config = array_merge($this->config, $auth);
        }
    }

    /**
     * 初始化
     * @param array $options 参数
     * @return 对象实例|static
     */
    public static function instance($options = [])
    {
        if (is_null(self::$instance)) {
            self::$instance = new static($options);
        }

        return self::$instance;
    }

    // $name 逗号分割的字符串或者字符串数组 是要验证的规则
    // $uid 认证用户的id
    // $relation 如果为 'or' 表示满足任一条规则即通过验证;如果为 'and' 则表示需满足所有规则才能通过验证
    // 返回 true(通过) 或者 false(不通过)
    /**
     * 检查权限
     * @param $name -- 要检查的规则
     * @param $uid -- 用户id
     * @param string $relation 与或
     * @return bool
     */
    public function check($name, $uid, $relation = 'or')
    {
        // 如果不打开权限开关，则都通过，不用验证
        if (!$this->config['auth_on']) {
            return true;
        }

        // 获取用户的所有有效规则列表
        $authList = $this->getAuthList($uid);

        // $name最终转为数组
        // 如果传入的$name是字符串，则会先全部转小写，再分割为数组
        if (is_string($name)) {
            $name = strtolower($name);
            $name = explode(',', $name);
        }

        $list = []; // 保存$name数组中验证通过的规则名
        foreach ($authList as $v) {
            if (in_array($v, $name, true)) {
                $list[] = $v;
            }
        }
        if ('or' == $relation && !empty($list)) {
            return true;
        }

        $diff = array_diff($name, $list);
        if ('and' == $relation && empty($diff)) {
            return true;
        }

        return false;
    }

    /**
     * 获取用户组，外部也可以调用
     * @param $uid -- 用户id
     * @return array|mixed
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    public function getGroups($uid)
    {
        static $groups = [];
        if (isset($groups[$uid])) {
            return $groups[$uid];
        }

        // 转换表名
        $auth_group_access = $this->config['auth_group_access'];
        $auth_group = $this->config['auth_group'];

        // 执行查询
        $userGroups = Db::view($auth_group_access, 'uid,group_id')
            ->view($auth_group, 'title,rules', "{$auth_group_access}.group_id={$auth_group}.id", 'left')
            ->where("{$auth_group_access}.uid={$uid} and {$auth_group}.status=1")
            ->select();

        $groups[$uid] = $userGroups->isEmpty() ? [] : $userGroups->toArray();

        return $groups[$uid];
    }

    /**
     * 获取权限列表
     * @param $uid -- 用户id
     * @return array|mixed
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    protected function getAuthList($uid)
    {
        static $_authList = []; // 保存用户验证通过的权限列表

        if (isset($_authList[$uid])) {
            return $_authList[$uid];
        }

        if (2 == $this->config['auth_type'] && Session::has('_auth_list_' . $uid)) {
            return Session::get('_auth_list_' . $uid);
        }

        // 读取用户所属用户组
        $groups = $this->getGroups($uid);
        $ids = []; // 保存用户所属用户组设置的所有权限规则id
        foreach ($groups as $g) {
            $ids = array_merge($ids, explode(',', trim($g['rules'], ',')));
        }
        $ids = array_unique($ids);
        if (empty($ids)) {
            $_authList[$uid] = [];

            return [];
        }

        // 读取用户组所有权限规则
        $rules = Db::name($this->config['auth_rule'])->where(['id' => ['in', $ids]])->field('condition,name')->select();
        // 循环规则，判断结果
        $authList = [];
        if (!$rules->isEmpty()) {
            $rules = $rules->toArray();
            foreach ($rules as $r) {
                if (!empty($r['condition'])) {
                    // 根据condition进行验证
                    $user = $this->getUserInfo($uid); // 获取用户信息，一维数组
                    // 用自定义的strOp()函数来运算字符串规则
                    if ($this->strOp($r['condition'], $user)) {
                        $authList[] = $r['name'];
                    }
                } else {
                    // 存在就通过
                    $authList[] = $r['name'];
                }
            }
            $_authList[$uid] = $authList;

            if (2 == $this->config['auth_type']) {
                // 规则列表结果保存到session
                Session::set('_auth_list_' . $uid, $authList);
            }
        }

        return $authList;
    }

    /**
     * 获取用户资料，根据自己的情况读取数据库
     * @param $uid -- 用户id
     * @return array|mixed|Db|\think\Model|null
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    protected function getUserInfo($uid)
    {
        static $userInfo = [];

        $user = Db::name($this->config['auth_user']);
        // 获取用户主键
        $_pk = is_string($user->getPk()) ? $user->getPk() : 'uid';

        if (!isset($userInfo[$uid])) {
            $userInfo[$uid] = $user->where($_pk, $uid)->find();
        }

        return $userInfo[$uid];
    }

    /**
     * 字符串运算
     * @param $str -- 字符串
     * @param $data -- 用户数据
     * @return bool|mixed|null
     * $str 示例 $str = "score<50 && score<100 || name!=abc"; （abc不能用单引号或双引号包裹）
     * $data 示例 $data = ['score'=>30, 'name'=>'abc'];
     */
    protected function strOp($str, $data)
    {
        // 支持的运算符号
        $opStr = '>=><=<&&==||!=';
        // 去除空格
        $str = str_replace(" ", "", $str);
        $str = preg_replace('/[\n\r\t]/', '', $str);

        // 数据填充，得到不含变量的运算字符串
        foreach ($data as $k => $v) {
            $str = str_replace($k, $v, $str);
        }

        // 运算字符串转数组
        $len = mb_strlen($str, 'utf-8');
        $strArr = [];
        for ($i = 0; $i < $len; $i++) {
            $strArr[] = mb_substr($str, $i, 1, 'utf-8');
        }

        // 提取有效运算符
        $isContinue = false;
        $opArr = []; // 所有要运算的符号
        $valArr = []; // 要进行运算的值
        $opRes = []; // 除&&、||外的运算结果
        $andOrOpArr = []; // &&、||运算符号
        $record = 0; // 字符串截取的起点标记
        for ($i = 0; $i < $len; $i++) {
            if (strpos($opStr, $strArr[$i]) !== false) {
                if (strpos($opStr, $strArr[$i] . $strArr[$i + 1]) !== false) {
                    $isContinue = true;
                    $opArr[] = $strArr[$i] . $strArr[$i + 1];
                    $valArr[] = $this->getValStr($strArr, $record, $i - $record);
                    $record = $i + 2;
                } else {
                    if ($isContinue) {
                        $isContinue = false;
                    } else {
                        if (strpos('=&|', $strArr[$i]) === false) {
                            $opArr[] = $strArr[$i];
                            $valArr[] = $this->getValStr($strArr, $record, $i - $record);
                            $record = $i + 1;
                        }
                    }
                }
            }
        }
        $valArr[] = $this->getValStr($strArr, $record, $len - $record);

        // 运算除&&、||外的符号，并存储结果
        foreach ($opArr as $k => $v) {
            if (strpos('&&||', $v) !== false) {
                $andOrOpArr[] = $v;
                if ($v == '||' && $k == 0) {
                    // 第一个符号为||，如0||...的情况
                    $opRes[] = array_shift($valArr);
                }
                if ($v == '||' && count($valArr) == 1) {
                    // 最后一个符号为||，如：...||0的情况
                    $opRes[] = array_shift($valArr);
                }
            } else {
                $left = array_shift($valArr);
                $right = array_shift($valArr);
                $opRes[] = $this->opRes($v, $left, $right);
            }
        }

        // 判断$andOrOpArr的情况，有没&&，有没||，是否为空
        // 如果$andOrOpArr为空，则直接返回$opRes[0]
        // 如果$andOrOpArr只有&&
        // 如果$andOrOpArr只有||
        // 如果$andOrOpArr有&&也有||
        $res = false;
        if (empty($andOrOpArr)) {
            // 没有&&和||
            $res = array_shift($opRes);
        } else {
            if (in_array('&&', $andOrOpArr, true) && !in_array('||', $andOrOpArr, true)) {
                // 只有&&，没有||
                $res = true;
                foreach ($opRes as $v) {
                    if (!$v) {
                        $res = false;
                        break;
                    }
                }
            } else {
                if (!in_array('&&', $andOrOpArr, true) && in_array('||', $andOrOpArr, true)) {
                    // 没有&&，只有||
                    foreach ($opRes as $v) {
                        if ($v) {
                            $res = true;
                            break;
                        }
                    }
                } else {
                    if (in_array('&&', $andOrOpArr, true) && in_array('||', $andOrOpArr, true)) {
                        // 既有&&，也有||

                        // 最后要进行运算||的值
                        $lastOrOpValArr = [];

                        // 运算&&，并存储结果（剩下的全是&&和||运算，而&&优先级高于||）
                        foreach ($andOrOpArr as $v) {
                            if ($v == '&&') {
                                $left = array_shift($opRes);
                                $right = array_shift($opRes);
                                array_unshift($opRes, $left && $right);
                            } else {
                                $lastOrOpValArr[] = array_shift($opRes);
                            }

                            if (count($opRes) == 1) {
                                $lastOrOpValArr[] = array_shift($opRes);
                            }
                        }

                        // 运算||（剩下的全是||运算）
                        foreach ($lastOrOpValArr as $v) {
                            if ($v) {
                                $res = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        return $res; // 最终结果
    }

    /**
     * 运算函数
     * @param $str -- 运算符字符串
     * @param $left -- 左边数据
     * @param $right -- 右边数据
     * @return bool
     */
    protected function opRes($str, $left, $right)
    {
        $res = false;
        switch ($str) {
            case '>=':
                $res = $left >= $right;
                break;
            case '>':
                $res = $left > $right;
                break;
            case '<=':
                $res = $left <= $right;
                break;
            case '<':
                $res = $left < $right;
                break;
            case '==':
                $res = $left == $right;
                break;
            case '!=':
                $res = $left != $right;
                break;
        }

        return $res;
    }

    /**
     * 获取val值
     * @param $arr -- 数组
     * @param $start -- 下标
     * @param $length -- 长度
     * @return string
     */
    protected function getValStr($arr, $start, $length)
    {
        $val = '';
        for ($n = $start; $n < $start + $length; $n++) {
            $val .= $arr[$n];
        }

        return $val;
    }
}