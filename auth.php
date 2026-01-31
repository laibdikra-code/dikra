<?php
// php/auth.php - النسخة المصححة والمؤمنة بالكامل
declare(strict_types=1);

// إعدادات الوقت
date_default_timezone_set('Africa/Algiers');

// بدء الجلسة الآمنة
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => isset($_SERVER['HTTPS']),
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true,
    'use_only_cookies' => true,
    'cookie_lifetime' => 86400, // 24 ساعة
    'gc_maxlifetime' => 1800, // 30 دقيقة
]);

// رؤوس الأمان
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// CORS محدود
$allowedOrigins = [
    'http://localhost',
    'http://127.0.0.1',
    'https://localhost'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
}

header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// معالجة طلبات OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// تحميل ملف التهيئة
require_once 'config.php';

// ==============================================
// 🛡️  دوال الأمان المساعدة
// ==============================================

/**
 * التحقق من معدل المحاولات لمنع هجمات Brute Force
 */
function checkRateLimit(string $key, int $maxAttempts = 5, int $lockoutTime = 900): bool {
    $ip = $_SERVER['REMOTE_ADDR'];
    $cacheKey = "login_attempts_{$ip}_{$key}";
    
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = [];
    }
    
    $currentTime = time();
    
    // تنظيف المحاولات القديمة
    $_SESSION['login_attempts'] = array_filter(
        $_SESSION['login_attempts'],
        fn($attempt) => ($currentTime - $attempt['time']) < $lockoutTime
    );
    
    // عد محاولات هذا المفتاح في آخر فترة زمنية
    $attemptsCount = count(array_filter(
        $_SESSION['login_attempts'],
        fn($attempt) => $attempt['key'] === $key
    ));
    
    if ($attemptsCount >= $maxAttempts) {
        // حساب الوقت المتبقي للحظر
        $firstAttempt = min(array_column(
            array_filter($_SESSION['login_attempts'], fn($a) => $a['key'] === $key),
            'time'
        ));
        $timeLeft = $lockoutTime - ($currentTime - $firstAttempt);
        
        error_log("حظر محاولات تسجيل دخول للعنوان $ip - المفتاح: $key - المحاولات: $attemptsCount");
        
        throw new Exception("تم تجاوز عدد المحاولات المسموح بها. الرجاء المحاولة بعد " . ceil($timeLeft / 60) . " دقيقة");
    }
    
    return true;
}

/**
 * تسجيل محاولة تسجيل دخول
 */
function recordLoginAttempt(string $key, bool $success): void {
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = [];
    }
    
    $_SESSION['login_attempts'][] = [
        'key' => $key,
        'time' => time(),
        'success' => $success,
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
    ];
    
    // حفظ فقط آخر 100 محاولة
    if (count($_SESSION['login_attempts']) > 100) {
        $_SESSION['login_attempts'] = array_slice($_SESSION['login_attempts'], -100);
    }
}

/**
 * التحقق من CSRF Token مع تحسينات الأمان
 */
function verifyCSRFToken(string $token = null): bool {
    // استقبال التوكن من الرأس أو البيانات المرسلة
    if (!$token) {
        $headers = getallheaders();
        $token = $headers['X-CSRF-Token'] ?? $_POST['csrf_token'] ?? '';
    }
    
    if (empty($token) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    
    // التحقق من انتهاء صلاحية التوكن (ساعة واحدة)
    if (isset($_SESSION['csrf_token_time']) && (time() - $_SESSION['csrf_token_time']) > 3600) {
        unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
        return false;
    }
    
    // استخدام hash_equals لمنع هجمات التوقيت
    $isValid = hash_equals($_SESSION['csrf_token'], $token);
    
    if ($isValid) {
        // إعادة توليد التوكن بعد الاستخدام الناجح
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    return $isValid;
}

/**
 * توليد CSRF Token جديد
 */
function generateCSRFToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    return $_SESSION['csrf_token'];
}

/**
 * تنظيف وتحقق من بيانات الإدخال
 */
function validateLoginInput(string $username, string $password): array {
    $errors = [];
    
    // التحقق من اسم المستخدم
    $username = trim($username);
    if (empty($username)) {
        $errors[] = 'اسم المستخدم مطلوب';
    } elseif (strlen($username) < 3) {
        $errors[] = 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل';
    } elseif (strlen($username) > 50) {
        $errors[] = 'اسم المستخدم لا يمكن أن يتجاوز 50 حرفاً';
    } elseif (!preg_match('/^[a-zA-Z0-9@._\-]+$/', $username)) {
        $errors[] = 'اسم المستخدم يحتوي على أحرف غير مسموحة';
    }
    
    // التحقق من كلمة المرور
    $password = trim($password);
    if (empty($password)) {
        $errors[] = 'كلمة المرور مطلوبة';
    } elseif (strlen($password) < 6) {
        $errors[] = 'كلمة المرور يجب أن تكون 6 أحرف على الأقل';
    } elseif (strlen($password) > 255) {
        $errors[] = 'كلمة المرور طويلة جداً';
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors,
        'username' => $username,
        'password' => $password
    ];
}

// ==============================================
// 🔄  معالجة الطلبات الرئيسية
// ==============================================

try {
    // استقبال البيانات
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        
        if (strpos($contentType, 'application/json') !== false) {
            $input = json_decode(file_get_contents('php://input'), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception('بيانات JSON غير صالحة');
            }
        } else {
            $input = $_POST;
        }
    } else {
        throw new Exception('الطريقة غير مسموحة. استخدم POST فقط');
    }
    
    $action = $input['action'] ?? '';
    
    // الاتصال بقاعدة البيانات
    $pdo = connectDB();
    
    switch ($action) {
        case 'login':
            handleLogin($pdo, $input);
            break;
            
        case 'logout':
            handleLogout();
            break;
            
        case 'check_auth':
            checkAuthStatus();
            break;
            
        case 'register':
            handleRegister($pdo, $input);
            break;
            
        case 'forgot_password':
            handleForgotPassword($pdo, $input);
            break;
            
        case 'reset_password':
            handleResetPassword($pdo, $input);
            break;
            
        case 'change_password':
            handleChangePassword($pdo, $input);
            break;
            
        default:
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'عملية غير معروفة',
                'available_actions' => [
                    'login',
                    'logout',
                    'check_auth',
                    'register',
                    'forgot_password',
                    'reset_password',
                    'change_password'
                ]
            ], JSON_UNESCAPED_UNICODE);
            exit;
    }
    
} catch (PDOException $e) {
    error_log("خطأ في قاعدة البيانات - auth.php: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'خطأ في الخادم. الرجاء المحاولة لاحقاً.'
    ], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    error_log("خطأ في auth.php: " . $e->getMessage());
    
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ], JSON_UNESCAPED_UNICODE);
}

// ==============================================
// 🔑  دوال المصادقة الرئيسية
// ==============================================

/**
 * معالجة تسجيل الدخول
 */
function handleLogin(PDO $pdo, array $input): void {
    // التحقق من CSRF Token للطلبات POST
    if (!verifyCSRFToken($input['csrf_token'] ?? '')) {
        throw new Exception('رمز التحقق غير صالح أو منتهي الصلاحية');
    }
    
    $username = $input['username'] ?? '';
    $password = $input['password'] ?? '';
    $remember = $input['remember'] ?? false;
    
    // التحقق من بيانات الإدخال
    $validation = validateLoginInput($username, $password);
    if (!$validation['valid']) {
        throw new Exception(implode(' ', $validation['errors']));
    }
    
    $username = $validation['username'];
    $password = $validation['password'];
    
    // التحقق من معدل المحاولات
    checkRateLimit($username);
    
    // البحث عن المستخدم باستخدام Matricule أو Email
    $stmt = $pdo->prepare("
        SELECT 
            id,
            matricule,
            nom,
            prenom,
            email,
            telephone,
            fonction,
            role,
            password_hash,
            is_active,
            last_login,
            failed_login_attempts,
            account_locked_until,
            created_at
        FROM employee 
        WHERE (matricule = :username OR email = :username)
        LIMIT 1
    ");
    
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        // تسجيل محاولة فاشلة
        recordLoginAttempt($username, false);
        
        // تأخير قصير لمنع هجمات Brute Force
        usleep(random_int(500000, 1500000)); // 0.5-1.5 ثانية
        
        throw new Exception('اسم المستخدم أو كلمة المرور غير صحيحة');
    }
    
    // التحقق من حالة الحساب
    if (!$user['is_active']) {
        throw new Exception('الحساب غير نشط. الرجاء التواصل مع الإدارة');
    }
    
    // التحقق من قفل الحساب
    if ($user['account_locked_until'] && strtotime($user['account_locked_until']) > time()) {
        $lockTime = strtotime($user['account_locked_until']) - time();
        throw new Exception("الحساب مؤقتاً مغلق. الرجاء المحاولة بعد " . ceil($lockTime / 60) . " دقيقة");
    }
    
    // التحقق من كلمة المرور
    if (!password_verify($password, $user['password_hash'])) {
        // زيادة عدد المحاولات الفاشلة
        $failedAttempts = $user['failed_login_attempts'] + 1;
        
        // قفل الحساب بعد 5 محاولات فاشلة لمدة 15 دقيقة
        if ($failedAttempts >= 5) {
            $lockUntil = date('Y-m-d H:i:s', time() + 900); // 15 دقيقة
            $updateStmt = $pdo->prepare("
                UPDATE employee 
                SET failed_login_attempts = :attempts, 
                    account_locked_until = :lock_until 
                WHERE id = :id
            ");
            $updateStmt->execute([
                ':attempts' => $failedAttempts,
                ':lock_until' => $lockUntil,
                ':id' => $user['id']
            ]);
            
            throw new Exception('تم تجاوز عدد المحاولات المسموح بها. الحساب مغلق لمدة 15 دقيقة');
        } else {
            // تحديث عدد المحاولات الفاشلة
            $updateStmt = $pdo->prepare("
                UPDATE employee 
                SET failed_login_attempts = :attempts 
                WHERE id = :id
            ");
            $updateStmt->execute([
                ':attempts' => $failedAttempts,
                ':id' => $user['id']
            ]);
        }
        
        // تسجيل محاولة فاشلة
        recordLoginAttempt($username, false);
        
        throw new Exception('اسم المستخدم أو كلمة المرور غير صحيحة');
    }
    
    // إذا وصلنا هنا، كلمة المرور صحيحة
    // إعادة تعيين عدد المحاولات الفاشلة وقفل الحساب
    $updateStmt = $pdo->prepare("
        UPDATE employee 
        SET failed_login_attempts = 0, 
            account_locked_until = NULL,
            last_login = NOW() 
        WHERE id = :id
    ");
    $updateStmt->execute([':id' => $user['id']]);
    
    // تسجيل محاولة ناجحة
    recordLoginAttempt($username, true);
    
    // إعادة توليد معرف الجلسة لمنع هجمات Session Fixation
    session_regenerate_id(true);
    
    // تخزين بيانات المستخدم في الجلسة
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_matricule'] = $user['matricule'];
    $_SESSION['user_name'] = $user['nom'] . ' ' . $user['prenom'];
    $_SESSION['user_first_name'] = $user['prenom'];
    $_SESSION['user_last_name'] = $user['nom'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['user_role'] = $user['role'];
    $_SESSION['user_fonction'] = $user['fonction'];
    $_SESSION['logged_in'] = true;
    $_SESSION['login_time'] = time();
    $_SESSION['last_activity'] = time();
    $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $_SESSION['session_id'] = session_id();
    
    // إذا طلب تذكر الدخول، إنشاء تذكرت آمنة
    if ($remember) {
        setRememberMeCookie($user['id']);
    }
    
    // تسجيل نشاط تسجيل الدخول
    logActivity('LOGIN_SUCCESS', [
        'user_id' => $user['id'],
        'matricule' => $user['matricule'],
        'ip' => $_SERVER['REMOTE_ADDR']
    ], $user['id']);
    
    // إنشاء CSRF Token جديد للجلسة
    generateCSRFToken();
    
    // الاستجابة الناجحة
    echo json_encode([
        'success' => true,
        'message' => 'مرحباً ' . $user['prenom'],
        'user' => [
            'id' => $user['id'],
            'matricule' => $user['matricule'],
            'name' => $user['nom'] . ' ' . $user['prenom'],
            'first_name' => $user['prenom'],
            'last_name' => $user['nom'],
            'email' => $user['email'],
            'role' => $user['role'],
            'fonction' => $user['fonction']
        ],
        'csrf_token' => $_SESSION['csrf_token'],
        'redirect' => determineRedirectUrl($user['role'])
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * معالجة تسجيل الخروج
 */
function handleLogout(): void {
    // تسجيل نشاط تسجيل الخروج
    if (isset($_SESSION['user_id'])) {
        logActivity('LOGOUT', [
            'user_id' => $_SESSION['user_id'],
            'matricule' => $_SESSION['user_matricule'] ?? ''
        ], $_SESSION['user_id']);
    }
    
    // حذف تذكرت الدخول إذا وجدت
    if (isset($_COOKIE['remember_me'])) {
        $pdo = connectDB();
        $token = $_COOKIE['remember_me'];
        $stmt = $pdo->prepare("DELETE FROM remember_me_tokens WHERE token = :token");
        $stmt->execute([':token' => hash('sha256', $token)]);
        
        setcookie('remember_me', '', time() - 3600, '/', '', true, true);
    }
    
    // إزالة جميع بيانات الجلسة
    $_SESSION = [];
    
    // إذا تم تعيين الكوكيز، قم بإلغائها
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }
    
    // تدمير الجلسة
    session_destroy();
    
    echo json_encode([
        'success' => true,
        'message' => 'تم تسجيل الخروج بنجاح',
        'redirect' => 'login.html'
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * التحقق من حالة المصادقة
 */
function checkAuthStatus(): void {
    // التحقق من انتهاء مدة الجلسة (30 دقيقة)
    $sessionTimeout = 30 * 60;
    
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time'] > $sessionTimeout)) {
        session_destroy();
        echo json_encode(['authenticated' => false]);
        return;
    }
    
    // التحقق من تغيير IP أو User Agent
    if (isset($_SESSION['user_ip']) && $_SESSION['user_ip'] !== $_SERVER['REMOTE_ADDR']) {
        session_destroy();
        echo json_encode(['authenticated' => false]);
        return;
    }
    
    if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
        session_destroy();
        echo json_encode(['authenticated' => false]);
        return;
    }
    
    // تحديث وقت النشاط الأخير
    if (isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
    }
    
    // التحقق من وجود بيانات المستخدم
    if (isset($_SESSION['user_id'], $_SESSION['logged_in'])) {
        // توليد CSRF Token جديد إذا لم يكن موجوداً
        if (empty($_SESSION['csrf_token'])) {
            generateCSRFToken();
        }
        
        echo json_encode([
            'authenticated' => true,
            'user' => [
                'id' => $_SESSION['user_id'],
                'matricule' => $_SESSION['user_matricule'] ?? '',
                'name' => $_SESSION['user_name'] ?? '',
                'first_name' => $_SESSION['user_first_name'] ?? '',
                'last_name' => $_SESSION['user_last_name'] ?? '',
                'email' => $_SESSION['user_email'] ?? '',
                'role' => $_SESSION['user_role'] ?? 'employe',
                'fonction' => $_SESSION['user_fonction'] ?? ''
            ],
            'csrf_token' => $_SESSION['csrf_token']
        ], JSON_UNESCAPED_UNICODE);
    } else {
        // التحقق من تذكرت الدخول
        if (isset($_COOKIE['remember_me'])) {
            try {
                $pdo = connectDB();
                $token = $_COOKIE['remember_me'];
                $hashedToken = hash('sha256', $token);
                
                $stmt = $pdo->prepare("
                    SELECT u.* 
                    FROM employee u
                    INNER JOIN remember_me_tokens r ON u.id = r.user_id
                    WHERE r.token = :token 
                    AND r.expires_at > NOW()
                    AND u.is_active = 1
                ");
                
                $stmt->execute([':token' => $hashedToken]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($user) {
                    // إنشاء جلسة جديدة
                    session_regenerate_id(true);
                    
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_matricule'] = $user['matricule'];
                    $_SESSION['user_name'] = $user['nom'] . ' ' . $user['prenom'];
                    $_SESSION['user_first_name'] = $user['prenom'];
                    $_SESSION['user_last_name'] = $user['nom'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_role'] = $user['role'];
                    $_SESSION['user_fonction'] = $user['fonction'];
                    $_SESSION['logged_in'] = true;
                    $_SESSION['login_time'] = time();
                    $_SESSION['last_activity'] = time();
                    $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
                    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                    
                    // تحديث وقت انتهاء التوكن
                    $updateStmt = $pdo->prepare("
                        UPDATE remember_me_tokens 
                        SET expires_at = DATE_ADD(NOW(), INTERVAL 30 DAY) 
                        WHERE token = :token
                    ");
                    $updateStmt->execute([':token' => $hashedToken]);
                    
                    // تحديث آخر دخول
                    $updateUserStmt = $pdo->prepare("
                        UPDATE employee 
                        SET last_login = NOW() 
                        WHERE id = :id
                    ");
                    $updateUserStmt->execute([':id' => $user['id']]);
                    
                    echo json_encode([
                        'authenticated' => true,
                        'user' => [
                            'id' => $user['id'],
                            'matricule' => $user['matricule'],
                            'name' => $user['nom'] . ' ' . $user['prenom'],
                            'role' => $user['role'],
                            'fonction' => $user['fonction']
                        ]
                    ], JSON_UNESCAPED_UNICODE);
                    return;
                }
            } catch (Exception $e) {
                // تجاهل الخطأ والاستمرار
                error_log("خطأ في تذكرت الدخول: " . $e->getMessage());
            }
        }
        
        echo json_encode(['authenticated' => false]);
    }
}

/**
 * معالجة تسجيل مستخدم جديد
 */
function handleRegister(PDO $pdo, array $input): void {
    // التحقق من CSRF Token
    if (!verifyCSRFToken($input['csrf_token'] ?? '')) {
        throw new Exception('رمز التحقق غير صالح');
    }
    
    $matricule = trim($input['matricule'] ?? '');
    $firstName = trim($input['first_name'] ?? '');
    $lastName = trim($input['last_name'] ?? '');
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';
    $confirmPassword = $input['confirm_password'] ?? '';
    $fonction = trim($input['fonction'] ?? '');
    $telephone = trim($input['telephone'] ?? '');
    
    // التحقق من البيانات المطلوبة
    $errors = [];
    
    if (empty($matricule)) $errors[] = 'رقم التسجيل مطلوب';
    if (empty($firstName)) $errors[] = 'الاسم الأول مطلوب';
    if (empty($lastName)) $errors[] = 'الاسم الأخير مطلوب';
    if (empty($email)) $errors[] = 'البريد الإلكتروني مطلوب';
    if (empty($password)) $errors[] = 'كلمة المرور مطلوبة';
    if (empty($fonction)) $errors[] = 'الوظيفة مطلوبة';
    
    if ($password !== $confirmPassword) {
        $errors[] = 'كلمتا المرور غير متطابقتين';
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'البريد الإلكتروني غير صالح';
    }
    
    if (strlen($password) < 8) {
        $errors[] = 'كلمة المرور يجب أن تكون 8 أحرف على الأقل';
    }
    
    if (!empty($errors)) {
        throw new Exception(implode('<br>', $errors));
    }
    
    // التحقق من عدم تكرار رقم التسجيل أو البريد
    $checkStmt = $pdo->prepare("
        SELECT id FROM employee 
        WHERE matricule = :matricule OR email = :email
    ");
    $checkStmt->execute([
        ':matricule' => $matricule,
        ':email' => $email
    ]);
    
    if ($checkStmt->fetch()) {
        throw new Exception('رقم التسجيل أو البريد الإلكتروني مستخدم بالفعل');
    }
    
    // إنشاء حساب جديد
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    
    $insertStmt = $pdo->prepare("
        INSERT INTO employee (
            matricule, 
            nom, 
            prenom, 
            email, 
            telephone, 
            fonction, 
            role, 
            password_hash, 
            is_active, 
            created_at
        ) VALUES (
            :matricule,
            :nom,
            :prenom,
            :email,
            :telephone,
            :fonction,
            'employe',
            :password_hash,
            0, -- غير نشط حتى تفعيله من قبل المسؤول
            NOW()
        )
    ");
    
    $insertStmt->execute([
        ':matricule' => $matricule,
        ':nom' => $lastName,
        ':prenom' => $firstName,
        ':email' => $email,
        ':telephone' => $telephone,
        ':fonction' => $fonction,
        ':password_hash' => $passwordHash
    ]);
    
    $userId = $pdo->lastInsertId();
    
    // تسجيل النشاط
    logActivity('REGISTER', [
        'user_id' => $userId,
        'matricule' => $matricule,
        'email' => $email
    ]);
    
    echo json_encode([
        'success' => true,
        'message' => 'تم إنشاء الحساب بنجاح! يرجى انتظار تفعيله من قبل المسؤول.',
        'user_id' => $userId
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * معالجة طلب إعادة تعيين كلمة المرور
 */
function handleForgotPassword(PDO $pdo, array $input): void {
    $email = trim($input['email'] ?? '');
    
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('البريد الإلكتروني غير صالح');
    }
    
    // التحقق من وجود المستخدم
    $stmt = $pdo->prepare("
        SELECT id, matricule, nom, prenom 
        FROM employee 
        WHERE email = :email AND is_active = 1
    ");
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        // عدم إفشاء معلومات عن وجود الحساب
        echo json_encode([
            'success' => true,
            'message' => 'إذا كان البريد الإلكتروني مسجلاً لدينا، ستتلقى رابط إعادة التعيين قريباً.'
        ], JSON_UNESCAPED_UNICODE);
        return;
    }
    
    // إنشاء رمز إعادة تعيين
    $resetToken = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $resetToken);
    $expiresAt = date('Y-m-d H:i:s', time() + 3600); // ساعة واحدة
    
    // حفظ التوكن في قاعدة البيانات
    $tokenStmt = $pdo->prepare("
        INSERT INTO password_reset_tokens (
            user_id, 
            token_hash, 
            expires_at, 
            created_at
        ) VALUES (
            :user_id,
            :token_hash,
            :expires_at,
            NOW()
        )
    ");
    
    $tokenStmt->execute([
        ':user_id' => $user['id'],
        ':token_hash' => $tokenHash,
        ':expires_at' => $expiresAt
    ]);
    
    // إنشاء رابط إعادة التعيين
    $resetLink = "https://" . $_SERVER['HTTP_HOST'] . "/reset-password.html?token=" . urlencode($resetToken);
    
    // هنا يمكنك إرسال البريد الإلكتروني
    // sendResetEmail($user['email'], $user['prenom'], $resetLink);
    
    // تسجيل النشاط
    logActivity('FORGOT_PASSWORD_REQUEST', [
        'user_id' => $user['id'],
        'email' => $email
    ], $user['id']);
    
    echo json_encode([
        'success' => true,
        'message' => 'تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني.',
        'token' => $resetToken, // في الإنتاج، لا ترسل التوكن
        'expires_at' => $expiresAt
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * معالجة إعادة تعيين كلمة المرور
 */
function handleResetPassword(PDO $pdo, array $input): void {
    $token = $input['token'] ?? '';
    $password = $input['password'] ?? '';
    $confirmPassword = $input['confirm_password'] ?? '';
    
    if (empty($token)) {
        throw new Exception('رمز إعادة التعيين مطلوب');
    }
    
    if ($password !== $confirmPassword) {
        throw new Exception('كلمتا المرور غير متطابقتين');
    }
    
    if (strlen($password) < 8) {
        throw new Exception('كلمة المرور يجب أن تكون 8 أحرف على الأقل');
    }
    
    // التحقق من صلاحية التوكن
    $tokenHash = hash('sha256', $token);
    
    $stmt = $pdo->prepare("
        SELECT prt.*, u.id as user_id, u.email
        FROM password_reset_tokens prt
        INNER JOIN employee u ON prt.user_id = u.id
        WHERE prt.token_hash = :token_hash 
        AND prt.expires_at > NOW()
        AND prt.used = 0
        AND u.is_active = 1
    ");
    
    $stmt->execute([':token_hash' => $tokenHash]);
    $resetToken = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$resetToken) {
        throw new Exception('رمز إعادة التعيين غير صالح أو منتهي الصلاحية');
    }
    
    // تحديث كلمة المرور
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    
    $updateStmt = $pdo->prepare("
        UPDATE employee 
        SET password_hash = :password_hash,
            failed_login_attempts = 0,
            account_locked_until = NULL
        WHERE id = :user_id
    ");
    
    $updateStmt->execute([
        ':password_hash' => $passwordHash,
        ':user_id' => $resetToken['user_id']
    ]);
    
    // تعليم التوكن كمستخدم
    $markUsedStmt = $pdo->prepare("
        UPDATE password_reset_tokens 
        SET used = 1, 
            used_at = NOW() 
        WHERE id = :id
    ");
    
    $markUsedStmt->execute([':id' => $resetToken['id']]);
    
    // تسجيل النشاط
    logActivity('PASSWORD_RESET', [
        'user_id' => $resetToken['user_id'],
        'email' => $resetToken['email']
    ], $resetToken['user_id']);
    
    echo json_encode([
        'success' => true,
        'message' => 'تم إعادة تعيين كلمة المرور بنجاح.'
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * معالجة تغيير كلمة المرور
 */
function handleChangePassword(PDO $pdo, array $input): void {
    // التحقق من CSRF Token
    if (!verifyCSRFToken($input['csrf_token'] ?? '')) {
        throw new Exception('رمز التحقق غير صالح');
    }
    
    // التحقق من تسجيل الدخول
    if (!isset($_SESSION['user_id'])) {
        throw new Exception('يجب تسجيل الدخول أولاً');
    }
    
    $currentPassword = $input['current_password'] ?? '';
    $newPassword = $input['new_password'] ?? '';
    $confirmPassword = $input['confirm_password'] ?? '';
    $userId = $_SESSION['user_id'];
    
    if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
        throw new Exception('جميع الحقول مطلوبة');
    }
    
    if ($newPassword !== $confirmPassword) {
        throw new Exception('كلمتا المرور الجديدة غير متطابقتين');
    }
    
    if (strlen($newPassword) < 8) {
        throw new Exception('كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل');
    }
    
    // جلب بيانات المستخدم الحالية
    $stmt = $pdo->prepare("
        SELECT password_hash 
        FROM employee 
        WHERE id = :id
    ");
    
    $stmt->execute([':id' => $userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        throw new Exception('المستخدم غير موجود');
    }
    
    // التحقق من كلمة المرور الحالية
    if (!password_verify($currentPassword, $user['password_hash'])) {
        throw new Exception('كلمة المرور الحالية غير صحيحة');
    }
    
    // عدم السماح باستخدام نفس كلمة المرور القديمة
    if (password_verify($newPassword, $user['password_hash'])) {
        throw new Exception('لا يمكن استخدام كلمة المرور الحالية');
    }
    
    // تحديث كلمة المرور
    $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
    
    $updateStmt = $pdo->prepare("
        UPDATE employee 
        SET password_hash = :password_hash,
            password_changed_at = NOW()
        WHERE id = :id
    ");
    
    $updateStmt->execute([
        ':password_hash' => $newPasswordHash,
        ':id' => $userId
    ]);
    
    // إرسال إشعار بتغيير كلمة المرور
    logActivity('PASSWORD_CHANGED', [
        'user_id' => $userId,
        'matricule' => $_SESSION['user_matricule']
    ], $userId);
    
    echo json_encode([
        'success' => true,
        'message' => 'تم تغيير كلمة المرور بنجاح.'
    ], JSON_UNESCAPED_UNICODE);
}

// ==============================================
// 🔧  دوال مساعدة
// ==============================================

/**
 * تحديد رابط التوجيه بناءً على الدور
 */
function determineRedirectUrl(string $role): string {
    switch ($role) {
        case 'admin':
            return 'dashboard.html';
        case 'magasinier':
            return 'dashboard.html';
        default: // employe
            return 'index.html';
    }
}

/**
 * إنشاء تذكرت دخول آمنة
 */
function setRememberMeCookie(int $userId): void {
    $pdo = connectDB();
    
    // إنشاء توكن عشوائي
    $token = bin2hex(random_bytes(32));
    $hashedToken = hash('sha256', $token);
    $expiresAt = date('Y-m-d H:i:s', time() + (30 * 24 * 3600)); // 30 يوم
    
    // حفظ التوكن في قاعدة البيانات
    $stmt = $pdo->prepare("
        INSERT INTO remember_me_tokens (
            user_id, 
            token, 
            expires_at, 
            created_at
        ) VALUES (
            :user_id,
            :token,
            :expires_at,
            NOW()
        )
    ");
    
    $stmt->execute([
        ':user_id' => $userId,
        ':token' => $hashedToken,
        ':expires_at' => $expiresAt
    ]);
    
    // تعيين الكوكي الآمن
    $cookieOptions = [
        'expires' => time() + (30 * 24 * 3600),
        'path' => '/',
        'domain' => '',
        'secure' => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict'
    ];
    
    setcookie('remember_me', $token, $cookieOptions);
}

/**
 * تسجيل النشاط في السجلات
 */
function logActivity(string $action, array $details = [], int $userId = null): void {
    try {
        $pdo = connectDB();
        
        $stmt = $pdo->prepare("
            INSERT INTO logs (
                action, 
                table_name, 
                record_id, 
                user_id,
                details,
                ip_address,
                user_agent
            ) VALUES (
                :action,
                :table_name,
                :record_id,
                :user_id,
                :details,
                :ip_address,
                :user_agent
            )
        ");
        
        $stmt->execute([
            ':action' => $action,
            ':table_name' => 'auth',
            ':record_id' => $userId ?? 0,
            ':user_id' => $userId,
            ':details' => json_encode($details, JSON_UNESCAPED_UNICODE),
            ':ip_address' => $_SERVER['REMOTE_ADDR'],
            ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    } catch (Exception $e) {
        error_log("فشل تسجيل النشاط: " . $e->getMessage());
    }
}
?>