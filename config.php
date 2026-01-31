<?php
// config.php - النسخة المحسنة والمؤمنة بالكامل
declare(strict_types=1);

// ==============================================
// ⚠️  إعدادات الأمان - لا تعدل هذه القيم يدوياً
// ==============================================

// إخفاء أخطاء PHP في بيئة الإنتاج
if (getenv('APP_ENV') === 'production') {
    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
    error_reporting(0);
} else {
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    error_reporting(E_ALL);
}

// منع الوصول المباشر للملفات الحساسة
if (basename($_SERVER['PHP_SELF']) == 'config.php') {
    header('HTTP/1.0 403 Forbidden');
    die('الوصول المباشر إلى هذا الملف غير مسموح.');
}

// ==============================================
// 🔐  إعدادات الجلسة الآمنة
// ==============================================

session_start([
    'name' => 'APP_SESSION',
    'cookie_lifetime' => 86400, // 24 ساعة
    'cookie_secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true,
    'use_only_cookies' => true,
    'use_trans_sid' => false,
    'gc_maxlifetime' => 1800, // 30 دقيقة
    'gc_probability' => 1,
    'gc_divisor' => 100,
    'referer_check' => '',
    'entropy_file' => '/dev/urandom',
    'entropy_length' => 32,
    'hash_function' => 'sha256',
    'hash_bits_per_character' => 6
]);

// ==============================================
// 🗄️  إعدادات قاعدة البيانات - من ملف .env
// ==============================================

class Config {
    private static $instance = null;
    private $config = [];
    
    private function __construct() {
        $this->loadEnv();
    }
    
    public static function getInstance(): self {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function loadEnv(): void {
        // محاولة تحميل من ملف .env
        $envFile = __DIR__ . '/.env';
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos(trim($line), '#') === 0) continue;
                
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                // إزالة الاقتباس من القيمة
                $value = trim($value, '"\'');
                
                $this->config[$key] = $value;
                putenv("$key=$value");
            }
        }
        
        // القيم الافتراضية
        $defaults = [
            'DB_HOST' => 'localhost',
            'DB_PORT' => '3306',
            'DB_NAME' => 'app_com',
            'DB_USER' => 'app_user',
            'DB_PASS' => '',
            'DB_CHARSET' => 'utf8mb4',
            'DB_COLLATION' => 'utf8mb4_unicode_ci',
            'APP_ENV' => 'development',
            'APP_KEY' => bin2hex(random_bytes(32)),
            'APP_URL' => 'http://localhost',
            'APP_NAME' => 'نظام إدارة المخزون',
            'SESSION_NAME' => 'app_session',
            'SESSION_LIFETIME' => '1440',
            'CSRF_TOKEN_NAME' => 'csrf_token',
            'UPLOAD_MAX_SIZE' => '10M',
            'TIMEZONE' => 'Africa/Algiers'
        ];
        
        foreach ($defaults as $key => $value) {
            if (!isset($this->config[$key])) {
                $this->config[$key] = getenv($key) ?: $value;
                putenv("$key={$this->config[$key]}");
            }
        }
        
        // إعداد المنطقة الزمنية
        date_default_timezone_set($this->config['TIMEZONE']);
    }
    
    public function get(string $key, $default = null) {
        return $this->config[$key] ?? $default;
    }
    
    public function all(): array {
        return $this->config;
    }
}

// ==============================================
// 📡  إعدادات HTTP والرؤوس الأمنية
// ==============================================

// إعداد رؤوس الأمان
function setSecurityHeaders(): void {
    $headers = [
        'X-Frame-Options' => 'DENY',
        'X-XSS-Protection' => '1; mode=block',
        'X-Content-Type-Options' => 'nosniff',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' https://cdnjs.cloudflare.com; font-src https://cdnjs.cloudflare.com; img-src 'self' data: https:",
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload'
    ];
    
    foreach ($headers as $name => $value) {
        header("$name: $value");
    }
}

// ==============================================
// 🛡️  دوال الحماية والأمان
// ==============================================

/**
 * اتصال آمن بقاعدة البيانات باستخدام PDO
 */
function connectDB(): PDO {
    $config = Config::getInstance();
    
    $dsn = sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=%s',
        $config->get('DB_HOST'),
        $config->get('DB_PORT'),
        $config->get('DB_NAME'),
        $config->get('DB_CHARSET')
    );
    
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_PERSISTENT => false,
        PDO::ATTR_STRINGIFY_FETCHES => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$config->get('DB_CHARSET')} COLLATE {$config->get('DB_COLLATION')}",
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
        PDO::MYSQL_ATTR_SSL_CA => null,
        PDO::MYSQL_ATTR_COMPRESS => true,
        PDO::MYSQL_ATTR_FOUND_ROWS => true
    ];
    
    try {
        $pdo = new PDO(
            $dsn,
            $config->get('DB_USER'),
            $config->get('DB_PASS'),
            $options
        );
        
        // إعدادات إضافية
        $pdo->exec("SET time_zone = '+01:00';");
        $pdo->exec("SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION';");
        
        return $pdo;
    } catch (PDOException $e) {
        // تسجيل الخطأ في ملف السجلات
        error_log(sprintf(
            "[%s] فشل الاتصال بقاعدة البيانات: %s",
            date('Y-m-d H:i:s'),
            $e->getMessage()
        ), 3, __DIR__ . '/logs/database.log');
        
        // عرض رسالة آمنة للمستخدم
        if (Config::getInstance()->get('APP_ENV') === 'development') {
            die(json_encode([
                'success' => false,
                'message' => 'فشل الاتصال بقاعدة البيانات: ' . $e->getMessage()
            ], JSON_UNESCAPED_UNICODE));
        } else {
            die(json_encode([
                'success' => false,
                'message' => 'خطأ في الخادم. الرجاء المحاولة لاحقاً.'
            ], JSON_UNESCAPED_UNICODE));
        }
    }
}

/**
 * التحقق من تسجيل الدخول مع حماية الجلسة
 */
function isLoggedIn(): bool {
    if (!isset($_SESSION['user_id'])) {
        return false;
    }
    
    // التحقق من صحة الجلسة
    $sessionChecks = [
        'user_id' => FILTER_VALIDATE_INT,
        'user_ip' => FILTER_VALIDATE_IP,
        'user_agent' => FILTER_SANITIZE_STRING,
        'login_time' => FILTER_VALIDATE_INT,
        'last_activity' => FILTER_VALIDATE_INT
    ];
    
    foreach ($sessionChecks as $key => $filter) {
        if (!isset($_SESSION[$key])) {
            return false;
        }
    }
    
    // التحقق من انتهاء مدة الجلسة (30 دقيقة)
    $sessionTimeout = Config::getInstance()->get('SESSION_LIFETIME', 30) * 60;
    if (time() - $_SESSION['last_activity'] > $sessionTimeout) {
        session_destroy();
        return false;
    }
    
    // التحقق من تغيير IP أو User Agent
    if ($_SESSION['user_ip'] !== $_SERVER['REMOTE_ADDR']) {
        session_destroy();
        return false;
    }
    
    if ($_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
        session_destroy();
        return false;
    }
    
    // تحديث وقت النشاط الأخير
    $_SESSION['last_activity'] = time();
    
    return true;
}

/**
 * التحقق من الصلاحيات مع هرمية الأدوار
 */
function hasPermission(string $requiredPermission, array $userPermissions = []): bool {
    if (!isLoggedIn()) {
        return false;
    }
    
    $userRole = $_SESSION['user_role'] ?? 'employe';
    
    // تعريف هرمية الأدوار
    $roleHierarchy = [
        'employe' => 1,
        'magasinier' => 2,
        'admin' => 3,
        'superadmin' => 4
    ];
    
    // صلاحيات كل دور
    $rolePermissions = [
        'employe' => ['view_own_orders', 'create_orders', 'view_articles'],
        'magasinier' => ['view_all_orders', 'validate_orders', 'manage_stock', 'view_reports'],
        'admin' => ['manage_users', 'system_settings', 'view_logs', 'backup_database'],
        'superadmin' => ['all']
    ];
    
    // إذا كان المستخدم سوبر أدمن، لديه كل الصلاحيات
    if ($userRole === 'superadmin') {
        return true;
    }
    
    // التحقق من وجود الدور في الهيراركية
    if (!isset($roleHierarchy[$userRole])) {
        return false;
    }
    
    // الحصول على صلاحيات الدور
    $permissions = array_merge(
        $rolePermissions[$userRole] ?? [],
        $userPermissions
    );
    
    // التحقق من الصلاحية المطلوبة
    return in_array($requiredPermission, $permissions) || in_array('all', $permissions);
}

/**
 * التحقق من مستوى الدور
 */
function checkRoleAccess(string $requiredRole): bool {
    if (!isLoggedIn()) {
        return false;
    }
    
    $userRole = $_SESSION['user_role'] ?? 'employe';
    
    $roleHierarchy = [
        'employe' => 1,
        'magasinier' => 2,
        'admin' => 3,
        'superadmin' => 4
    ];
    
    $userLevel = $roleHierarchy[$userRole] ?? 0;
    $requiredLevel = $roleHierarchy[$requiredRole] ?? 0;
    
    return $userLevel >= $requiredLevel;
}

/**
 * توليد CSRF Token آمن
 */
function generateCSRFToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    return $_SESSION['csrf_token'];
}

/**
 * التحقق من CSRF Token مع التحقق من الوقت
 */
function verifyCSRFToken(string $token, int $maxAge = 3600): bool {
    if (!isset($_SESSION['csrf_token'], $_SESSION['csrf_token_time'])) {
        return false;
    }
    
    // التحقق من انتهاء الصلاحية
    if (time() - $_SESSION['csrf_token_time'] > $maxAge) {
        unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
        return false;
    }
    
    // استخدام hash_equals لمنع هجمات التوقيت
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * تنظيف البيانات المدخلة بشكل شامل
 */
function sanitizeInput($data, string $type = 'string') {
    if (is_array($data)) {
        return array_map(fn($item) => sanitizeInput($item, $type), $data);
    }
    
    if ($data === null || $data === '') {
        return null;
    }
    
    // إزالة المسافات الزائدة
    $data = trim($data);
    
    // إزالة الشرط المائلة
    $data = stripslashes($data);
    
    // التحقق حسب النوع
    switch ($type) {
        case 'int':
            return filter_var($data, FILTER_VALIDATE_INT, [
                'options' => ['min_range' => 0]
            ]);
            
        case 'float':
            return filter_var($data, FILTER_VALIDATE_FLOAT);
            
        case 'email':
            $email = filter_var($data, FILTER_VALIDATE_EMAIL);
            return $email ? strtolower($email) : null;
            
        case 'url':
            return filter_var($data, FILTER_VALIDATE_URL);
            
        case 'bool':
            return filter_var($data, FILTER_VALIDATE_BOOLEAN);
            
        case 'date':
            $date = DateTime::createFromFormat('Y-m-d', $data);
            return $date ? $date->format('Y-m-d') : null;
            
        case 'datetime':
            $datetime = DateTime::createFromFormat('Y-m-d H:i:s', $data);
            return $datetime ? $datetime->format('Y-m-d H:i:s') : null;
            
        case 'html':
            // السماح ببعض وسوم HTML الآمنة
            $allowedTags = '<p><br><b><strong><i><em><u><ul><ol><li><a><img><table><tr><td><th><h1><h2><h3><h4><h5><h6>';
            $data = strip_tags($data, $allowedTags);
            $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            return $data;
            
        case 'password':
            // لا تقم بتنظيف كلمات المرور
            return $data;
            
        default: // string
            $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $data = preg_replace('/[^\p{L}\p{N}\s\-_.,@]/u', '', $data);
            return $data;
    }
}

/**
 * إعادة توجيه آمن
 */
function redirect(string $url, int $statusCode = 302): void {
    // التحقق من أن الرابط ضمن النطاق
    $baseUrl = Config::getInstance()->get('APP_URL');
    if (strpos($url, 'http') !== 0) {
        $url = rtrim($baseUrl, '/') . '/' . ltrim($url, '/');
    }
    
    // التحقق من أن الرابط ينتمي لنفس النطاق
    if (parse_url($url, PHP_URL_HOST) !== parse_url($baseUrl, PHP_URL_HOST)) {
        $url = $baseUrl;
    }
    
    header("Location: $url", true, $statusCode);
    exit;
}

/**
 * تسجيل النشاط في السجلات
 */
function logActivity(string $action, array $details = [], int $userId = null): void {
    $config = Config::getInstance();
    $logDir = __DIR__ . '/logs';
    
    // إنشاء مجلد السجلات إذا لم يكن موجوداً
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    $userId = $userId ?? ($_SESSION['user_id'] ?? 0);
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    
    $logEntry = sprintf(
        "[%s] UserID: %d | Action: %s | IP: %s | Agent: %s | Details: %s\n",
        date('Y-m-d H:i:s'),
        $userId,
        $action,
        $ipAddress,
        $userAgent,
        json_encode($details, JSON_UNESCAPED_UNICODE)
    );
    
    $logFile = $logDir . '/activity-' . date('Y-m-d') . '.log';
    
    // كتابة السجل
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    
    // الحفاظ على السجلات لـ 30 يوماً فقط
    $daysToKeep = 30;
    $files = glob($logDir . '/activity-*.log');
    
    foreach ($files as $file) {
        if (filemtime($file) < time() - ($daysToKeep * 86400)) {
            @unlink($file);
        }
    }
}

/**
 * التحقق من قوة كلمة المرور
 */
function validatePassword(string $password): array {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = 'كلمة المرور يجب أن تحتوي على 8 أحرف على الأقل';
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'كلمة المرور يجب أن تحتوي على حرف كبير على الأقل';
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'كلمة المرور يجب أن تحتوي على حرف صغير على الأقل';
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'كلمة المرور يجب أن تحتوي على رقم على الأقل';
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = 'كلمة المرور يجب أن تحتوي على رمز خاص على الأقل';
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors
    ];
}

/**
 * تشفير البيانات الحساسة
 */
function encryptData(string $data, string $key = null): string {
    $key = $key ?? Config::getInstance()->get('APP_KEY');
    $method = 'AES-256-CBC';
    $ivLength = openssl_cipher_iv_length($method);
    $iv = openssl_random_pseudo_bytes($ivLength);
    
    $encrypted = openssl_encrypt($data, $method, $key, 0, $iv);
    
    return base64_encode($iv . $encrypted);
}

/**
 * فك تشفير البيانات
 */
function decryptData(string $data, string $key = null): string {
    $key = $key ?? Config::getInstance()->get('APP_KEY');
    $method = 'AES-256-CBC';
    
    $data = base64_decode($data);
    $ivLength = openssl_cipher_iv_length($method);
    $iv = substr($data, 0, $ivLength);
    $encrypted = substr($data, $ivLength);
    
    return openssl_decrypt($encrypted, $method, $key, 0, $iv);
}

/**
 * التحقق من معدل الطلبات (Rate Limiting)
 */
function checkRateLimit(string $key, int $maxRequests = 60, int $timeWindow = 60): bool {
    $config = Config::getInstance();
    $cacheDir = __DIR__ . '/cache';
    
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0755, true);
    }
    
    $cacheFile = $cacheDir . '/ratelimit-' . md5($key) . '.json';
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        
        if ($data['time'] > time() - $timeWindow) {
            if ($data['count'] >= $maxRequests) {
                return false;
            }
            $data['count']++;
        } else {
            $data = ['count' => 1, 'time' => time()];
        }
    } else {
        $data = ['count' => 1, 'time' => time()];
    }
    
    file_put_contents($cacheFile, json_encode($data));
    
    // تنظيف الملفات القديمة
    $files = glob($cacheDir . '/ratelimit-*.json');
    foreach ($files as $file) {
        if (filemtime($file) < time() - 3600) {
            @unlink($file);
        }
    }
    
    return true;
}

/**
 * إنشاء رمز تحقق فريد
 */
function generateVerificationCode(int $length = 6): string {
    $characters = '0123456789';
    $code = '';
    
    for ($i = 0; $i < $length; $i++) {
        $code .= $characters[random_int(0, strlen($characters) - 1)];
    }
    
    return $code;
}

/**
 * التحقق من صحة ملف الرفع
 */
function validateUploadedFile(array $file, array $allowedTypes = ['image/jpeg', 'image/png', 'application/pdf']): array {
    $maxSize = Config::getInstance()->get('UPLOAD_MAX_SIZE', '10M');
    $maxBytes = convertToBytes($maxSize);
    
    $errors = [];
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = 'خطأ في رفع الملف';
        return ['valid' => false, 'errors' => $errors];
    }
    
    // التحقق من الحجم
    if ($file['size'] > $maxBytes) {
        $errors[] = "حجم الملف يتجاوز الحد المسموح ($maxSize)";
    }
    
    // التحقق من النوع
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    if (!in_array($mimeType, $allowedTypes)) {
        $errors[] = 'نوع الملف غير مسموح به';
    }
    
    // التحقق من الامتداد
    $allowedExtensions = [];
    foreach ($allowedTypes as $type) {
        $allowedExtensions[] = mime2ext($type);
    }
    
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, $allowedExtensions)) {
        $errors[] = 'امتداد الملف غير مسموح به';
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors,
        'mime_type' => $mimeType,
        'extension' => $extension
    ];
}

/**
 * تحويل حجم الملف إلى بايت
 */
function convertToBytes(string $size): int {
    $unit = strtoupper(substr($size, -1));
    $value = (int) substr($size, 0, -1);
    
    switch ($unit) {
        case 'G': return $value * 1024 * 1024 * 1024;
        case 'M': return $value * 1024 * 1024;
        case 'K': return $value * 1024;
        default: return $value;
    }
}

/**
 * تحويل نوع MIME إلى امتداد
 */
function mime2ext(string $mime): string {
    $mimeMap = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        'application/pdf' => 'pdf',
        'application/msword' => 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/vnd.ms-excel' => 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx'
    ];
    
    return $mimeMap[$mime] ?? 'bin';
}

/**
 * إنشاء رابط آمن
 */
function secureUrl(string $path): string {
    $config = Config::getInstance();
    $baseUrl = rtrim($config->get('APP_URL'), '/');
    $path = ltrim($path, '/');
    
    return $baseUrl . '/' . $path;
}

// ==============================================
// 🚀  تهيئة النظام
// ==============================================

// تهيئة التكوين
$config = Config::getInstance();

// إعداد رؤوس الأمان
setSecurityHeaders();

// إنشاء مجلدات النظام إذا لم تكن موجودة
$requiredDirs = ['logs', 'cache', 'uploads', 'backups'];
foreach ($requiredDirs as $dir) {
    $dirPath = __DIR__ . '/' . $dir;
    if (!is_dir($dirPath)) {
        mkdir($dirPath, 0755, true);
        // إضافة ملف .htaccess للحماية
        file_put_contents($dirPath . '/.htaccess', "Deny from all\n");
    }
}

// تسجيل بدء الجلسة
if (!isset($_SESSION['session_id'])) {
    $_SESSION['session_id'] = session_id();
    $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $_SESSION['login_time'] = time();
    $_SESSION['last_activity'] = time();
    
    // توليد CSRF Token تلقائياً
    generateCSRFToken();
}

// ==============================================
// 📋  ثوابت النظام
// ==============================================

define('APP_NAME', $config->get('APP_NAME'));
define('APP_ENV', $config->get('APP_ENV'));
define('APP_URL', $config->get('APP_URL'));
define('APP_KEY', $config->get('APP_KEY'));
define('DB_HOST', $config->get('DB_HOST'));
define('DB_NAME', $config->get('DB_NAME'));
define('TIMEZONE', $config->get('TIMEZONE'));

// إصدار النظام
define('APP_VERSION', '2.0.0');
define('DB_VERSION', '1.0.0');

// ==============================================
// 📊  دوال التصحيح (للتطوير فقط)
// ==============================================

if (APP_ENV === 'development') {
    function dd($data): void {
        echo '<pre>';
        var_dump($data);
        echo '</pre>';
        die();
    }
    
    function dump($data): void {
        echo '<pre>';
        var_dump($data);
        echo '</pre>';
    }
}

// ==============================================
// 🔄  معالجة الأخطاء المخصصة
// ==============================================

set_error_handler(function($errno, $errstr, $errfile, $errline) {
    if (!(error_reporting() & $errno)) {
        return false;
    }
    
    $errorTypes = [
        E_ERROR => 'Error',
        E_WARNING => 'Warning',
        E_PARSE => 'Parse Error',
        E_NOTICE => 'Notice',
        E_CORE_ERROR => 'Core Error',
        E_CORE_WARNING => 'Core Warning',
        E_COMPILE_ERROR => 'Compile Error',
        E_COMPILE_WARNING => 'Compile Warning',
        E_USER_ERROR => 'User Error',
        E_USER_WARNING => 'User Warning',
        E_USER_NOTICE => 'User Notice',
        E_STRICT => 'Strict Notice',
        E_RECOVERABLE_ERROR => 'Recoverable Error',
        E_DEPRECATED => 'Deprecated',
        E_USER_DEPRECATED => 'User Deprecated'
    ];
    
    $errorType = $errorTypes[$errno] ?? 'Unknown Error';
    
    $logMessage = sprintf(
        "[%s] %s: %s in %s on line %d\n",
        date('Y-m-d H:i:s'),
        $errorType,
        $errstr,
        $errfile,
        $errline
    );
    
    error_log($logMessage, 3, __DIR__ . '/logs/errors.log');
    
    if (APP_ENV === 'production') {
        return true;
    }
    
    return false;
});

set_exception_handler(function($exception) {
    $logMessage = sprintf(
        "[%s] Exception: %s in %s on line %d\nStack Trace:\n%s\n",
        date('Y-m-d H:i:s'),
        $exception->getMessage(),
        $exception->getFile(),
        $exception->getLine(),
        $exception->getTraceAsString()
    );
    
    error_log($logMessage, 3, __DIR__ . '/logs/exceptions.log');
    
    if (APP_ENV === 'production') {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'حدث خطأ غير متوقع في النظام'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    throw $exception;
});

register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        $logMessage = sprintf(
            "[%s] Fatal Error: %s in %s on line %d\n",
            date('Y-m-d H:i:s'),
            $error['message'],
            $error['file'],
            $error['line']
        );
        
        error_log($logMessage, 3, __DIR__ . '/logs/fatal.log');
        
        if (APP_ENV === 'production') {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'message' => 'حدث خطأ جسيم في النظام'
            ], JSON_UNESCAPED_UNICODE);
        }
    }
});
?>